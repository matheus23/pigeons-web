//! Thin glue over the browser APIs this app needs.

use js_sys::{Array, Object, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CryptoKey, Document, EventTarget, IdbDatabase, IdbRequest, IdbTransactionMode, SubtleCrypto,
    Window,
};

pub type Result<T> = std::result::Result<T, String>;

pub fn window() -> Window {
    web_sys::window().expect("a window")
}

pub fn document() -> Document {
    window().document().expect("a document")
}

pub fn storage() -> Option<web_sys::Storage> {
    window().local_storage().ok().flatten()
}

/// Fetches an element by id, panicking if the markup is wrong. The page ships
/// with the markup this crate expects, so a missing node is a build mistake.
pub fn by_id<T: JsCast>(id: &str) -> T {
    let element = document()
        .get_element_by_id(id)
        .unwrap_or_else(|| panic!("missing #{id}"));
    element
        .dyn_into::<T>()
        .unwrap_or_else(|_| panic!("#{id} has the wrong type"))
}

pub fn element(tag: &str, class: &str) -> web_sys::HtmlElement {
    let el: web_sys::HtmlElement = document()
        .create_element(tag)
        .expect("create element")
        .dyn_into()
        .expect("element");
    if !class.is_empty() {
        el.set_class_name(class);
    }
    el
}

/// Replaces an element's children with a single text node.
pub fn set_text(parent: &web_sys::Node, text: &str) {
    parent.set_text_content(Some(text));
}

/// Registers an event listener that lives for the page's lifetime.
pub fn on<T: JsCast>(target: &EventTarget, event: &str, mut handler: impl FnMut(T) + 'static) {
    let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        if let Ok(typed) = event.dyn_into::<T>() {
            handler(typed);
        }
    });
    target
        .add_event_listener_with_callback(event, callback.as_ref().unchecked_ref())
        .expect("add listener");
    callback.forget();
}

/// Reports an unrecoverable startup problem in the page.
pub fn fatal(message: &str) {
    let node: web_sys::HtmlElement = by_id("boot-error");
    node.set_class_name("boot-error visible");
    set_text(&node, message);
}

pub fn log(message: &str) {
    web_sys::console::log_1(&JsValue::from_str(message));
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Randomness from the platform CSPRNG, used for key exchange and padding.
pub struct BrowserRng;

impl kereru::Randomness for BrowserRng {
    fn fill(&mut self, out: &mut [u8]) {
        let crypto = window().crypto().expect("crypto");
        crypto
            .get_random_values_with_u8_array(out)
            .expect("getRandomValues");
    }
}

// ---------------------------------------------------------------------------
// WebCrypto
// ---------------------------------------------------------------------------

pub fn subtle() -> SubtleCrypto {
    window().crypto().expect("crypto").subtle()
}

pub fn object(bytes: &[u8]) -> Object {
    Object::from(JsValue::from(Uint8Array::from(bytes)))
}

pub fn bytes_of(value: JsValue) -> Result<Vec<u8>> {
    if value.is_null() || value.is_undefined() {
        return Err("empty buffer".into());
    }
    Ok(Uint8Array::new(&value).to_vec())
}

pub fn array_of(items: &[&str]) -> JsValue {
    let array = Array::new();
    for item in items {
        array.push(&JsValue::from_str(item));
    }
    JsValue::from(array)
}

// ---------------------------------------------------------------------------
// IndexedDB: non-extractable CryptoKeys cannot go in localStorage, but they are
// structured-cloneable, so a one-store database holds them across reloads.
// ---------------------------------------------------------------------------

const DB_NAME: &str = "pigeons-web";
const STORE: &str = "keys";

/// Awaits an IDB request, resolving to its `result`.
fn await_request(request: &IdbRequest) -> js_sys::Promise {
    let request = request.clone();
    js_sys::Promise::new(&mut move |resolve, reject| {
        let ok = {
            let request = request.clone();
            Closure::once_into_js(move |_event: web_sys::Event| {
                let value = request.result().unwrap_or(JsValue::NULL);
                let _ = resolve.call1(&JsValue::NULL, &value);
            })
        };
        let fail = Closure::once_into_js(move |_event: web_sys::Event| {
            let _ = reject.call1(&JsValue::NULL, &JsValue::from_str("indexeddb error"));
        });
        request.set_onsuccess(Some(ok.unchecked_ref()));
        request.set_onerror(Some(fail.unchecked_ref()));
    })
}

async fn open_database() -> Result<IdbDatabase> {
    let factory = window()
        .indexed_db()
        .map_err(|e| format!("indexeddb unavailable: {e:?}"))?
        .ok_or("indexeddb is disabled in this browser session")?;

    let request = factory
        .open(DB_NAME)
        .map_err(|e| format!("opening database: {e:?}"))?;

    let upgrade = Closure::once_into_js(move |event: web_sys::Event| {
        let request: IdbRequest = event.target().unwrap().unchecked_into();
        if let Ok(db) = request.result() {
            let db: IdbDatabase = db.unchecked_into();
            // Re-creating an existing store throws, which is harmless.
            let _ = db.create_object_store(STORE);
        }
    });
    request.set_onupgradeneeded(Some(upgrade.unchecked_ref()));

    let database = JsFuture::from(await_request(&request))
        .await
        .map_err(|e| format!("opening database: {e:?}"))?;
    Ok(database.unchecked_into())
}

fn store(database: &IdbDatabase, mode: IdbTransactionMode) -> Result<web_sys::IdbObjectStore> {
    let transaction = database
        .transaction_with_str_and_mode(STORE, mode)
        .map_err(|e| format!("opening transaction: {e:?}"))?;
    transaction
        .object_store(STORE)
        .map_err(|e| format!("opening store: {e:?}"))
}

pub async fn idb_get(key: &str) -> Result<Option<JsValue>> {
    let database = open_database().await?;
    let store = store(&database, IdbTransactionMode::Readonly)?;
    let request = store
        .get(&JsValue::from_str(key))
        .map_err(|e| format!("reading key: {e:?}"))?;
    let value = JsFuture::from(await_request(&request))
        .await
        .map_err(|e| format!("reading key: {e:?}"))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    Ok(Some(value))
}

pub async fn idb_put(key: &str, value: &JsValue) -> Result<()> {
    let database = open_database().await?;
    let store = store(&database, IdbTransactionMode::Readwrite)?;
    let request = store
        .put_with_key(value, &JsValue::from_str(key))
        .map_err(|e| format!("writing key: {e:?}"))?;
    JsFuture::from(await_request(&request))
        .await
        .map_err(|e| format!("writing key: {e:?}"))?;
    Ok(())
}

pub async fn idb_delete(key: &str) -> Result<()> {
    let database = open_database().await?;
    let store = store(&database, IdbTransactionMode::Readwrite)?;
    let request = store
        .delete(&JsValue::from_str(key))
        .map_err(|e| format!("deleting key: {e:?}"))?;
    JsFuture::from(await_request(&request))
        .await
        .map_err(|e| format!("deleting key: {e:?}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

pub async fn copy_text(text: &str) -> Result<()> {
    let clipboard = window().navigator().clipboard();
    JsFuture::from(clipboard.write_text(text))
        .await
        .map_err(|e| format!("clipboard write failed: {e:?}"))?;
    Ok(())
}
/// A one-shot timer, used to yield to the browser's event loop.
pub fn sleep(millis: i32) -> js_sys::Promise {
    js_sys::Promise::new(&mut |resolve, _reject| {
        let callback = Closure::once_into_js(move || {
            let _ = resolve.call0(&JsValue::NULL);
        });
        window()
            .set_timeout_with_callback_and_timeout_and_arguments_0(callback.unchecked_ref(), millis)
            .expect("setTimeout");
    })
}

/// Casts a stored `CryptoKey` back to its type.
pub fn as_crypto_key(value: JsValue) -> Result<CryptoKey> {
    value
        .dyn_into::<CryptoKey>()
        .map_err(|_| "stored value is not a CryptoKey".to_string())
}
