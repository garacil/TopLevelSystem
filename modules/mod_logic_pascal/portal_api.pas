{
  Author: Germán Luis Aracil Boned <garacilb@gmail.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <https://www.gnu.org/licenses/>.
}

{
  portal_api.pas — Portal API for Free Pascal applications

  Use: uses portal_api;

  Functions:
    portal_get(path): String
    portal_log(level, message)
    portal_register_path(path, module_name)
    portal_set_response(resp, status, body)
}
unit portal_api;

{$mode objfpc}{$H+}

interface

uses ctypes, SysUtils;

type
  PPortalCore = Pointer;
  PPortalMsg = Pointer;
  PPortalResp = Pointer;

  { Core API function pointers - match C struct portal_core }
  TPathRegister = function(core: PPortalCore; path: PChar; module_name: PChar): cint; cdecl;
  TPathUnregister = function(core: PPortalCore; path: PChar): cint; cdecl;
  TSend = function(core: PPortalCore; msg: PPortalMsg; resp: PPortalResp): cint; cdecl;

var
  G_Core: PPortalCore;

{ High-level API }
procedure portal_log(core: PPortalCore; level: Integer; module_name, msg: PChar);
procedure portal_set_response_body(resp: PPortalResp; status: Word; body: PChar; body_len: Integer);

implementation

procedure portal_log(core: PPortalCore; level: Integer; module_name, msg: PChar);
begin
  WriteLn('[', module_name, '] ', msg);
end;

procedure portal_set_response_body(resp: PPortalResp; status: Word; body: PChar; body_len: Integer);
begin
  { Direct memory write to resp struct - status at offset 0, body at offset 8 }
  PWord(resp)^ := status;
  { For now, the response is handled by the C wrapper }
end;

end.
