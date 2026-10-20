mod config;
mod identity;
mod platform;
mod terminal;
mod tunnel;
mod ui;

use wasm_bindgen::prelude::*;

/// Entry point: builds the page, then hands control to the UI.
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    wasm_bindgen_futures::spawn_local(async {
        if let Err(error) = ui::run().await {
            platform::fatal(&error);
        }
    });
    Ok(())
}
