(* A functional client interface to ldap

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
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*)

module Make (M : Ldap_types.Monad) = struct

open M
let (>>=) = bind
let (>|=) t f = bind t (fun x -> return (f x))

module Lber = Lber.Make(M)
module Ldap_protocol = Ldap_protocol.Make(M)

type msgid = Int32.t

type conn = {
  rb: Lber.readbyte;
  channels: (M.IO.input_channel * M.IO.output_channel);
  mutable current_msgid: Int32.t; (* the largest message id allocated so far *)
  pending_messages: (int32, Ldap_types.ldap_message Queue.t) Hashtbl.t;
  protocol_version: int;
}

type attr = { attr_name: string; attr_values: string list }
type modattr = Ldap_types.modify_optype * string * string list
type result = Ldap_types.search_result_entry list
type entry = Ldap_types.search_result_entry
type authmethod = [ `SIMPLE | `SASL ]
type search_result = [ `Entry of entry
                     | `Referral of (string list)
                     | `Success of (Ldap_types.ldap_controls option) ]
type page_control =
  [ `Noctrl
  | `Initctrl of int
  | `Subctrl of (int * string) ]

let ext_res = {Ldap_types.ext_matched_dn="";
               ext_referral=None}

(* limits us to Int32.max_int active async operations
   at any one time *)
let find_free_msgid con =
  let msgid = con.current_msgid in
    (if msgid = Int32.max_int then
       con.current_msgid <- 0l
     else
       con.current_msgid <- Int32.succ con.current_msgid);
    msgid

(* allocate a message id from the free message id pool *)
let allocate_messageid con =
  let msgid = find_free_msgid con in
    Hashtbl.replace con.pending_messages msgid (Queue.create ());
    msgid

let free_messageid con msgid =
  try Hashtbl.remove con.pending_messages msgid;
      return ()
  with Not_found ->
    fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "free_messageid: invalid msgid", ext_res))

(* send an ldapmessage *)
let send_message con msg : unit M.t =
  catch
    (fun () -> M.IO.write (snd con.channels) (Ldap_protocol.encode_ldapmessage msg))
    (function
         Unix.Unix_error (Unix.EBADF, _, _)
       | Unix.Unix_error (Unix.EPIPE, _, _)
       | Unix.Unix_error (Unix.ECONNRESET, _, _)
       | Unix.Unix_error (Unix.ECONNABORTED, _, _)
       | _ ->
           (fail
              (Ldap_types.LDAP_Failure
                 (`SERVER_DOWN,
                  "the connection object is invalid, data cannot be written",
                  ext_res))))

(* recieve an ldapmessage for a particular message id (messages for
   all other ids will be read and queued. They can be retreived later) *)
let receive_message con msgid =
  let q_for_msgid con msgid =
    try Hashtbl.find con.pending_messages msgid
    with Not_found -> raise (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid message id", ext_res))
  in
  let rec read_message con msgid =
    Ldap_protocol.decode_ldapmessage con.rb >>= fun msg ->
      if msg.Ldap_types.messageID = msgid then return msg
      else
        (let q = q_for_msgid con msg.Ldap_types.messageID in
           Queue.add msg q;
           read_message con msgid)
  in
  let q = q_for_msgid con msgid in
    try
      if Queue.is_empty q then
        read_message con msgid
      else return (Queue.take q)
    with
        Ldap_types.Readbyte_error Ldap_types.Transport_error ->
          raise (Ldap_types.LDAP_Failure (`SERVER_DOWN, "read error", ext_res))
      | Ldap_types.Readbyte_error Ldap_types.End_of_stream ->
          raise (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "bug in ldap decoder detected", ext_res))

let receive_message con msgid =
  catch
    (fun () -> receive_message con msgid)
    (fun exn -> fail exn)

let map_s f l =
  let rec map_s f acc = function
    | [] -> return (List.rev acc)
    | x :: tl -> f x >>= fun y -> map_s f (y :: acc) tl
  in
    map_s f [] l

let init ?(connect_timeout = 1) ?(version = 3) hosts =
  if ((version < 2) || (version > 3)) then
    fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid protocol version", ext_res))
  else
    let hosts =
      map_s
        (fun host ->
           (match Ldap_url.of_string host with
                {Ldap_types.url_mech=mech;url_host=(Some host);url_port=(Some port)} ->
                  return (mech, host, int_of_string port)
              | {Ldap_types.url_mech=`SSL;url_host=(Some host);url_port=None} ->
                  return (`SSL, host, 636)
              | {Ldap_types.url_mech=`PLAIN;url_host=(Some host);url_port=None} ->
                  return (`PLAIN, host, 389)
              | _ -> fail
                       (Ldap_types.LDAP_Failure
                          (`LOCAL_ERROR, "invalid ldap url", ext_res))))
        hosts
    in hosts >>= fun hosts ->

    let addrs =
      map_s
        (fun (mech, host, port) ->
           (* FIXME: support IPv6? (e.g. with optional param to init) *)
           M.IO.getaddrinfo host (string_of_int port)
             [Unix.AI_SOCKTYPE Unix.SOCK_STREAM; Unix.AI_FAMILY Unix.PF_INET] >|=
           List.map (fun ai -> (mech, ai.Unix.ai_addr)))
        hosts >|=
      List.flatten
    in addrs >>= fun addrs ->

    let rec open_con = function
      | [] -> fail (Ldap_types.LDAP_Failure (`SERVER_DOWN, "", ext_res))
      | (mech, addr) :: tl ->
          M.IO.connect mech ~connect_timeout addr >>= function
            | None -> open_con tl
            | Some (ic, oc) ->
                return
                { rb= M.IO.readbyte_of_input_channel ic;
                  channels = (ic, oc);
                  current_msgid=1l;
                  pending_messages=(Hashtbl.create 3);
                  protocol_version=version
                }
    in
      open_con addrs

(* sync auth_method types between the two files *)
let bind_s ?(who = "") ?(cred = "") ?(auth_method = `SIMPLE) con =
  let msgid = allocate_messageid con in
    finalize begin fun () ->
       send_message con
         {Ldap_types.messageID=msgid;
          Ldap_types.protocolOp=Ldap_types.Bind_request
                       {Ldap_types.bind_version=con.protocol_version;
                        bind_name=who;
                        bind_authentication=(Ldap_types.Simple cred)};
          controls=None} >>= fun () ->
       receive_message con msgid >>= function
           {Ldap_types.protocolOp=Ldap_types.Bind_response {Ldap_types.bind_result={Ldap_types.result_code=`SUCCESS}}} ->
             return ()
         | {Ldap_types.protocolOp=Ldap_types.Bind_response {Ldap_types.bind_result=res}} ->
             fail (Ldap_types.LDAP_Failure
                      (res.Ldap_types.result_code, res.Ldap_types.error_message,
                       {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                        ext_referral=res.Ldap_types.ldap_referral}))
         | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid server response", ext_res))
    end
      (fun () -> free_messageid con msgid)

let freemsg_on_error con msgid f =
  catch f (fun exn -> free_messageid con msgid >>= fun () -> catch (fun () -> raise exn) fail)

let search ?(base = "") ?(scope = `SUBTREE) ?(aliasderef=`NEVERDEREFALIASES)
  ?(sizelimit=0l) ?(timelimit=0l) ?(attrs = []) ?(attrsonly = false)
  ?(page_control = `Noctrl) con filter =
  let msgid = allocate_messageid con in
  let build_res_ctrl size cookie =
    {Ldap_types.criticality = false;
    Ldap_types.control_details=(`Paged_results_control {Ldap_types.size; Ldap_types.cookie})}
  in
    freemsg_on_error con msgid begin fun () ->
      let controls = match (page_control) with
        | `Noctrl -> None
        | `Initctrl size | `Subctrl (size,_) when size < 1 ->
          raise (Ldap_types.LDAP_Failure(`LOCAL_ERROR, "invalid page size", ext_res))
        | `Initctrl size -> Some [(build_res_ctrl size "")]
        | `Subctrl (size,cookie) -> Some [(build_res_ctrl size cookie)]
      in
      let e_filter = (try return (Ldap_filter.of_string filter)
                      with _ ->
                        (fail
                           (Ldap_types.LDAP_Failure
                              (`LOCAL_ERROR, "bad search filter", ext_res))))
      in e_filter >>= fun e_filter ->
        send_message con
          {Ldap_types.messageID=msgid;
           Ldap_types.protocolOp=Ldap_types.Search_request
                        {Ldap_types.baseObject=base;
                         scope=scope;
                         derefAliases=aliasderef;
                         sizeLimit=sizelimit;
                         timeLimit=timelimit;
                         typesOnly=attrsonly;
                         filter=e_filter;
                         s_attributes=attrs};
           controls} >|= fun _ ->
        msgid
    end

let get_search_entry con msgid =
  freemsg_on_error con msgid begin fun () ->
    receive_message con msgid >>= function
        {Ldap_types.protocolOp=Ldap_types.Search_result_entry e} -> return (`Entry e)
      | {Ldap_types.protocolOp=Ldap_types.Search_result_reference r} -> return (`Referral r)
      | {Ldap_types.protocolOp=Ldap_types.Search_result_done {Ldap_types.result_code=`SUCCESS}} ->
          fail (Ldap_types.LDAP_Failure (`SUCCESS, "success", ext_res))
      | {Ldap_types.protocolOp=Ldap_types.Search_result_done res} ->
        fail (Ldap_types.LDAP_Failure (res.Ldap_types.result_code, res.Ldap_types.error_message,
                             {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                              ext_referral=res.Ldap_types.ldap_referral}))
      | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "unexpected search response", ext_res))
  end

let get_search_entry_with_controls con msgid =
  freemsg_on_error con msgid begin fun () ->
    receive_message con msgid >>= function
        {Ldap_types.protocolOp=Ldap_types.Search_result_entry e} -> return (`Entry e)
      | {Ldap_types.protocolOp=Ldap_types.Search_result_reference r} -> return (`Referral r)
      | {Ldap_types.protocolOp=Ldap_types.Search_result_done {Ldap_types.result_code=`SUCCESS};Ldap_types.controls=cntrls} ->
        return (`Success cntrls)
      | {Ldap_types.protocolOp=Ldap_types.Search_result_done res} ->
        fail (Ldap_types.LDAP_Failure (res.Ldap_types.result_code, res.Ldap_types.error_message,
                             {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                              ext_referral=res.Ldap_types.ldap_referral}))
      | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "unexpected search response", ext_res))
  end

let abandon con msgid =
  let my_msgid = allocate_messageid con in
    finalize begin fun () ->
      free_messageid con msgid >>= fun () ->
      send_message con
        {Ldap_types.messageID=my_msgid;
         Ldap_types.protocolOp=(Ldap_types.Abandon_request msgid);
         controls=None}
    end
    (fun () -> free_messageid con my_msgid)

let search_s ?(base = "") ?(scope = `SUBTREE) ?(aliasderef=`NEVERDEREFALIASES)
  ?(sizelimit=0l) ?(timelimit=0l) ?(attrs = []) ?(attrsonly = false) con filter =
  search ~base:base ~scope:scope ~aliasderef:aliasderef ~sizelimit:sizelimit
         ~timelimit:timelimit ~attrs:attrs ~attrsonly:attrsonly con filter >>= fun msgid ->

  let rec loop results =
    begin
      catch
        (fun () -> get_search_entry con msgid >|= fun x -> `OK x)
        (fun exn -> return (`EXN exn))
    end >>=
    function
      | `OK x -> loop (x :: results)
      | `EXN (Ldap_types.LDAP_Failure (`SUCCESS, _, _)) ->
          free_messageid con msgid >>= fun () ->
          return results
      | `EXN (Ldap_types.LDAP_Failure (code, msg, ext)) -> fail (Ldap_types.LDAP_Failure (code, msg, ext))
      | `EXN exn ->
          catch (fun () -> abandon con msgid) (fun _ -> return ()) >>= fun () ->
          (* try to preserve backtrace *)
          catch (fun () -> raise exn) fail
  in
    loop []

let rec filter_map f l =
  let rec loop_filter_map f acc = function
    | [] -> List.rev acc
    | x :: tl ->
        match f x with
          | None -> loop_filter_map f acc tl
          | Some y -> loop_filter_map f (y :: acc) tl
  in
    loop_filter_map f [] l

let search_paged_s ?(base = "") ?(scope = `SUBTREE) ?(aliasderef=`NEVERDEREFALIASES)
  ?(timelimit=0l) ?(attrs = []) ?(attrsonly = false) ?(page_size=500) con filter =

  let rec loop results msgid =
    let open Ldap_types in
    begin
      catch
        (fun () -> get_search_entry_with_controls con msgid >|= fun x -> `OK x)
        (fun exn -> return (`EXN exn))
    end >>=
    function
      | `OK (`Entry _ | `Referral _ as x) -> loop (x :: results) msgid
      | `OK (`Success (Some cd)) -> begin
          match
            filter_map
              (function
                 | { control_details = `Paged_results_control { cookie; _ }; _ } -> Some cookie
                 | _ -> None)
              cd
          with
            | [] | ("" :: _) ->
                free_messageid con msgid >>= fun () ->
                return results
            | cookie :: _ ->
                freemsg_on_error con msgid
                  (fun () ->
                     search
                       ~page_control:(`Subctrl (max 1 page_size, cookie))
                       ~base ~scope ~aliasderef
                       ~timelimit ~attrs ~attrsonly con filter >>=
                     loop results)
        end
      | `OK (`Success None)
      | `EXN (Ldap_types.LDAP_Failure (`SUCCESS, _, _)) ->
          free_messageid con msgid >>= fun () ->
          return results
      | `EXN (Ldap_types.LDAP_Failure (code, msg, ext)) -> fail (Ldap_types.LDAP_Failure (code, msg, ext))
      | `EXN exn ->
          catch (fun () -> abandon con msgid) (fun _ -> return ()) >>= fun () ->
          (* try to preserve backtrace *)
          catch (fun () -> raise exn) fail
  in
    search
      ~page_control:(`Initctrl (max 1 page_size))
      ~base:base ~scope:scope ~aliasderef:aliasderef
      ~timelimit:timelimit ~attrs:attrs ~attrsonly:attrsonly con filter >>=
    loop []

let add_s con (entry: entry) =
  let msgid = allocate_messageid con in
    finalize begin fun () ->
       send_message con
         {Ldap_types.messageID=msgid;
          Ldap_types.protocolOp=Ldap_types.Add_request entry;
          controls=None} >>= fun () ->
       receive_message con msgid >>= function
           {Ldap_types.protocolOp=Ldap_types.Add_response {Ldap_types.result_code=`SUCCESS}} -> return ()
         | {Ldap_types.protocolOp=Ldap_types.Add_response res} ->
             fail (Ldap_types.LDAP_Failure (res.Ldap_types.result_code, res.Ldap_types.error_message,
                                  {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                                   ext_referral=res.Ldap_types.ldap_referral}))
         | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid add response", ext_res))
    end
    (fun () -> free_messageid con msgid)

let delete_s con ~dn =
  let msgid = allocate_messageid con in
    finalize begin fun () ->
       send_message con
         {Ldap_types.messageID=msgid;
          Ldap_types.protocolOp=Ldap_types.Delete_request dn;
          controls=None} >>= fun () ->
       receive_message con msgid >>= function
           {Ldap_types.protocolOp=Ldap_types.Delete_response {Ldap_types.result_code=`SUCCESS}} -> return ()
         | {Ldap_types.protocolOp=Ldap_types.Delete_response res} ->
             fail (Ldap_types.LDAP_Failure (res.Ldap_types.result_code, res.Ldap_types.error_message,
                                  {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                                   ext_referral=res.Ldap_types.ldap_referral}))
         | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid delete response", ext_res))
    end
    (fun () -> free_messageid con msgid)

let unbind con =
  M.IO.close_out (snd con.channels) >>= fun () ->
  M.IO.close_in (fst con.channels)

let modify_s con ~dn ~mods =
  let rec convertmods ?(converted=[]) mods =
    match mods with
        (op, attr, values) :: tl ->
          (convertmods
             ~converted:({Ldap_types.mod_op=op;
                          mod_value={Ldap_types.attr_type=attr;
                                     attr_vals=values}} :: converted)
             tl)
      | [] -> converted
  in
  let msgid = allocate_messageid con in
    finalize begin fun () ->
       send_message con
         {Ldap_types.messageID=msgid;
          Ldap_types.protocolOp=Ldap_types.Modify_request
                       {Ldap_types.mod_dn=dn;
                        modification=convertmods mods};
          controls=None} >>= fun () ->
       receive_message con msgid >>= function
           {Ldap_types.protocolOp=Ldap_types.Modify_response {Ldap_types.result_code=`SUCCESS}} -> return ()
         | {Ldap_types.protocolOp=Ldap_types.Modify_response res} ->
             fail (Ldap_types.LDAP_Failure (res.Ldap_types.result_code, res.Ldap_types.error_message,
                                  {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                                   ext_referral=res.Ldap_types.ldap_referral}))
         | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid modify response", ext_res))
    end
    (fun () -> free_messageid con msgid)

let modrdn_s ?(deleteoldrdn=true) ?(newsup=None) con ~dn ~newdn =
  let msgid = allocate_messageid con in
    finalize begin fun () ->
       send_message con
         {Ldap_types.messageID=msgid;
          Ldap_types.protocolOp=Ldap_types.Modify_dn_request
                       {Ldap_types.modn_dn=dn;
                        modn_newrdn=newdn;
                        modn_deleteoldrdn=deleteoldrdn;
                        modn_newSuperior=None};
          controls=None} >>= fun () ->
       receive_message con msgid >>= function
           {Ldap_types.protocolOp=Ldap_types.Modify_dn_response {Ldap_types.result_code=`SUCCESS}} -> return ()
         | {Ldap_types.protocolOp=Ldap_types.Modify_dn_response res} ->
             fail (Ldap_types.LDAP_Failure (res.Ldap_types.result_code, res.Ldap_types.error_message,
                                  {Ldap_types.ext_matched_dn=res.Ldap_types.matched_dn;
                                   ext_referral=res.Ldap_types.ldap_referral}))
         | _ -> fail (Ldap_types.LDAP_Failure (`LOCAL_ERROR, "invalid modify dn response", ext_res))
    end
    (fun () -> free_messageid con msgid)

let create_grouping_s groupingType value = return ()
let end_grouping_s cookie value = return ()

end
