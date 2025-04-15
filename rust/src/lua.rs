/* Copyright (C) 2017 Open Information Security Foundation
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

//! Lua wrapper module.

use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_long;
use std::os::raw::c_void;

use suricata_sys::sys::AppProto;

/// The Rust place holder for lua_State.
pub enum CLuaState {}

/// cbindgen:ignore
extern "C" {
    fn lua_createtable(lua: *mut CLuaState, narr: c_int, nrec: c_int);
    fn lua_settable(lua: *mut CLuaState, idx: c_long);
    fn lua_pushlstring(lua: *mut CLuaState, s: *const c_char, len: usize);
    fn lua_pushinteger(lua: *mut CLuaState, n: i64);

    pub(crate) fn luaL_newmetatable(lua: *mut CLuaState, s: *const c_char);
    pub(crate) fn lua_pushvalue(lua: *mut CLuaState, v: c_int);
    pub(crate) fn lua_setfield(lua: *mut CLuaState, v: c_int, s: *const c_char);
    pub(crate) fn luaL_setfuncs(lua: *mut CLuaState, regs: *const luaL_Reg, v: c_int);
    pub(crate) fn luaL_newlib(lua: *mut CLuaState, regs: *const luaL_Reg);
    pub(crate) fn luaL_getmetatable(lua: *mut CLuaState, s: *const c_char);
    pub(crate) fn lua_setmetatable(lua: *mut CLuaState, v: c_int);
    pub(crate) fn lua_newuserdata(lua: *mut CLuaState, v: usize) -> *mut c_void;
    pub(crate) fn luaL_testudata(lua: *mut CLuaState, v: c_int, s: *const c_char) -> *mut c_void;
    pub(crate) fn lua_pushnil(lua: *mut CLuaState);

    // from src/util-lua-common.h
    pub fn LuaStateNeedProto(lua: *mut CLuaState, alproto: AppProto) -> c_int;
    pub fn LuaCallbackError(lua: *mut CLuaState, msg: *const c_char) -> c_int;
    pub fn LuaStateGetTX(lua: *mut CLuaState) -> *mut c_void;

    // from src/util-lua.h
    pub fn LuaPushStringBuffer(lua: *mut CLuaState, b: *const u8, l: usize) -> c_int;
}

pub(crate) type LuaCfunction = unsafe extern "C" fn(lua: *mut CLuaState) -> c_int;

#[repr(C)]
pub(crate) struct luaL_Reg {
    pub name: *const c_char,
    pub func: Option<LuaCfunction>,
}

pub struct LuaState {
    pub lua: *mut CLuaState,
}

impl LuaState {

    pub fn newtable(&self) {
        unsafe {
            lua_createtable(self.lua, 0, 0);
        }
    }

    pub fn settable(&self, idx: i64) {
        unsafe {
            lua_settable(self.lua, idx as c_long);
        }
    }

    pub fn pushstring(&self, val: &str) {
        unsafe {
            lua_pushlstring(self.lua, val.as_ptr() as *const c_char, val.len());
        }
    }

    pub fn pushinteger(&self, val: i64) {
        unsafe {
            lua_pushinteger(self.lua, val);
        }
    }
}
