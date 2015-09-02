(* Functions which resemble the command line tools, useful in the
   interactive environment

   Copyright (C) 2004 Eric Stokes, and The California State University
   at Northridge

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA
*)

let eval s =
  let l = Lexing.from_string s in
  let ph = !Toploop.parse_toplevel_phrase l in
  assert(Toploop.execute_phrase false Format.err_formatter ph)
;;

eval "#install_printer Ldap_ooclient.format_entries;;";;
eval "#install_printer Ldap_ooclient.format_entry;;";;
eval "#install_printer Ldap_schema.format_oid;;";;
eval "#install_printer Ldap_schema.format_oidset;;";;
eval "#install_printer Ldap_schema.format_lcstring;;";;
eval "#install_printer Ldap_schema.format_schema;;";;

module Make (M : Ldap_types.Monad) = struct

open M
let (>>=) = bind
let (>|=) t f = bind t (fun x -> return (f x))

module Ldap_ooclient = Ldap_ooclient.Make(M)
open Ldap_ooclient
open Ldap_types
module Ldif_oo = Ldif_oo.Make(M)
open Ldif_oo
open Ldap_schema

let ldap_cmd_harness ~h ~d ~w f =
  let ldap = new ldapcon [h] in
    catch
      (fun () ->
         ldap#bind d ~cred:w >>= fun () ->
         f ldap >>= fun res ->
           ldap#unbind >>= fun () ->
           return res)
      (function exn -> ldap#unbind >>= fun () -> fail exn)

let ldapsearch ?(s=`SUBTREE) ?(a=[]) ?(b="") ?(d="") ?(w="") ~h filter =
  ldap_cmd_harness ~h ~d ~w
    (fun ldap ->
       ldap#search
         ~base:b ~scope:s
         ~attrs:a filter)

let rec iter_s f = function
  | [] -> return ()
  | x :: tl -> f x >>= fun () -> iter_s f tl

let ldapmodify ~h ~d ~w mods =
  ldap_cmd_harness ~h ~d ~w
    (fun ldap ->
       iter_s
         (fun (dn, ldmod) -> ldap#modify dn ldmod)
         mods)

let ldapadd ~h ~d ~w entries =
  ldap_cmd_harness ~h ~d ~w
    (fun ldap ->
       iter_s
         (fun entry -> ldap#add entry)
         entries)

end;;
