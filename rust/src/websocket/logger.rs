/* Copyright (C) 2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use super::websocket::WebSocketTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;
use suricata_derive::EnumStringU8;

#[derive(EnumStringU8)]
pub enum WebSocketOpcode {
    Continuation = 0,
    Text = 1,
    Binary = 2,
    Ping = 8,
    Pong = 9,
}

fn log_websocket(tx: &WebSocketTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("websocket")?;
    js.set_bool("mask", tx.pdu.mask)?;
    if let Some(val) = web_socket_opcode_string(tx.pdu.opcode) {
        js.set_string("opcode", val)?;
    } else {
        js.set_string("opcode", &format!("unknown-{}", tx.pdu.opcode))?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_websocket_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, WebSocketTransaction);
    log_websocket(tx, js).is_ok()
}
