/* Copyright (C) 2025 Open Information Security Foundation
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

use std::os::raw::{c_char, c_int, c_void};

use suricata_sys::sys::AppProto;
use suricata_sys::sys::AppProtoEnum::ALPROTO_SSH;

use crate::lua::{
    luaL_Reg, luaL_getmetatable, luaL_newlib, luaL_newmetatable, luaL_setfuncs, luaL_testudata,
    lua_newuserdata, lua_pushnil, lua_pushvalue, lua_setfield, lua_setmetatable, CLuaState,
    LuaCallbackError, LuaPushStringBuffer, LuaStateGetTX, LuaStateNeedProto,
};

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};

use super::detect::{SCSshTxGetProtocol, SCSshTxGetSoftware};

const SSH_TX: *const c_char = "suricata:ssh:tx\0".as_ptr() as *const c_char;

unsafe extern "C" fn ssh_lua_get_proto(lua: *mut CLuaState, direction: u8) -> c_int {
    let ltx = luaL_testudata(lua, 1, SSH_TX);
    if ltx.is_null() {
        lua_pushnil(lua);
        return 1;
    }
    let buf = std::ptr::null_mut();
    let mut b_len = 0u32;
    let ltx = cast_pointer!(ltx, LuaTx);
    if SCSshTxGetProtocol(ltx.tx, buf, &mut b_len as *mut u32, direction) != 1 {
        lua_pushnil(lua);
        return 1;
    }
    return LuaPushStringBuffer(lua, buf as *const u8, b_len as usize);
}

unsafe extern "C" fn ssh_lua_get_server_proto(lua: *mut CLuaState) -> c_int {
    return ssh_lua_get_proto(lua, STREAM_TOCLIENT);
}

unsafe extern "C" fn ssh_lua_get_client_proto(lua: *mut CLuaState) -> c_int {
    return ssh_lua_get_proto(lua, STREAM_TOSERVER);
}

unsafe extern "C" fn ssh_lua_get_soft(lua: *mut CLuaState, direction: u8) -> c_int {
    let ltx = luaL_testudata(lua, 1, SSH_TX);
    if ltx.is_null() {
        lua_pushnil(lua);
        return 1;
    }
    let buf = std::ptr::null_mut();
    let mut b_len = 0u32;
    let ltx = cast_pointer!(ltx, LuaTx);
    if SCSshTxGetSoftware(ltx.tx, buf, &mut b_len as *mut u32, direction) != 1 {
        lua_pushnil(lua);
        return 1;
    }
    return LuaPushStringBuffer(lua, buf as *const u8, b_len as usize);
}

unsafe extern "C" fn ssh_lua_get_server_soft(lua: *mut CLuaState) -> c_int {
    return ssh_lua_get_soft(lua, STREAM_TOCLIENT);
}

unsafe extern "C" fn ssh_lua_get_client_soft(lua: *mut CLuaState) -> c_int {
    return ssh_lua_get_soft(lua, STREAM_TOSERVER);
}

const TX_LIB: *const luaL_Reg = [
    luaL_Reg {
        name: "server_proto\0".as_ptr() as *const c_char,
        func: Some(ssh_lua_get_server_proto),
    },
    luaL_Reg {
        name: "client_proto\0".as_ptr() as *const c_char,
        func: Some(ssh_lua_get_client_proto),
    },
    luaL_Reg {
        name: "server_software\0".as_ptr() as *const c_char,
        func: Some(ssh_lua_get_server_soft),
    },
    luaL_Reg {
        name: "client_software\0".as_ptr() as *const c_char,
        func: Some(ssh_lua_get_client_soft),
    },
    luaL_Reg {
        name: std::ptr::null(),
        func: None,
    },
]
.as_ptr();

struct LuaTx {
    tx: *mut c_void, // SSHTransaction
}

unsafe extern "C" fn ssh_lua_get_tx(lua: *mut CLuaState) -> c_int {
    if LuaStateNeedProto(lua, ALPROTO_SSH as AppProto) != 0 {
        return LuaCallbackError(lua, "error: protocol not ssh\0".as_ptr() as *const c_char);
    }
    let tx = LuaStateGetTX(lua);
    if tx.is_null() {
        return LuaCallbackError(lua, "error: no tx available\0".as_ptr() as *const c_char);
    }
    let ltx = lua_newuserdata(lua, size_of::<LuaTx>());
    if ltx.is_null() {
        return LuaCallbackError(
            lua,
            "error: fail to allocate user data\0".as_ptr() as *const c_char,
        );
    }
    let ltx = cast_pointer!(ltx, LuaTx);
    ltx.tx = tx;

    luaL_getmetatable(lua, SSH_TX);
    lua_setmetatable(lua, -2);

    return 1;
}

const SSH_LIB: *const luaL_Reg = [
    luaL_Reg {
        name: "get_tx\0".as_ptr() as *const c_char,
        func: Some(ssh_lua_get_tx),
    },
    luaL_Reg {
        name: std::ptr::null(),
        func: None,
    },
]
.as_ptr();

#[no_mangle]
pub unsafe extern "C" fn SCLuaLoadSshLib(lua: *mut CLuaState) -> c_int {
    luaL_newmetatable(lua, SSH_TX);
    lua_pushvalue(lua, -1);
    lua_setfield(lua, -2, "__index\0".as_ptr() as *const c_char);
    luaL_setfuncs(lua, TX_LIB, 0);
    luaL_newlib(lua, SSH_LIB);

    return 1;
}
