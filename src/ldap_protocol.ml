(* An implementation of the ldap protocol, both client and server
   functions are implemented

   Copyright (C) 2004 Eric Stokes, Matthew Backes, and The California
   State University at Northridge

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

module Make (M : Ldap_types.Monad) = struct

open M
let (>>=) = bind
let (>|=) t f = bind t (fun x -> return (f x))

module Lber = Lber.Make(M)
open Lber
open Ldap_types

let encode_resultcode (code:ldap_resultcode) =
  match code with
      `SUCCESS -> 0
    | `OPERATIONS_ERROR -> 1
    | `PROTOCOL_ERROR -> 2
    | `TIMELIMIT_EXCEEDED -> 3
    | `SIZELIMIT_EXCEEDED -> 4
    | `COMPARE_FALSE -> 5
    | `COMPARE_TRUE -> 6
    | `AUTH_METHOD_NOT_SUPPORTED -> 7
    | `STRONG_AUTH_REQUIRED -> 8
    | `REFERRAL -> 10
    | `ADMINLIMIT_EXCEEDED -> 11
    | `UNAVAILABLE_CRITICAL_EXTENSION -> 12
    | `CONFIDENTIALITY_REQUIRED -> 13
    | `SASL_BIND_IN_PROGRESS -> 14
    | `NO_SUCH_ATTRIBUTE -> 16
    | `UNDEFINED_TYPE -> 17
    | `INAPPROPRIATE_MATCHING -> 18
    | `CONSTRAINT_VIOLATION -> 19
    | `TYPE_OR_VALUE_EXISTS -> 20
    | `INVALID_SYNTAX -> 21
    | `NO_SUCH_OBJECT -> 32
    | `ALIAS_PROBLEM -> 33
    | `INVALID_DN_SYNTAX -> 34
    | `IS_LEAF -> 35
    | `ALIAS_DEREF_PROBLEM -> 36
    | `INAPPROPRIATE_AUTH -> 48
    | `INVALID_CREDENTIALS -> 49
    | `INSUFFICIENT_ACCESS -> 50
    | `BUSY -> 51
    | `UNAVAILABLE -> 52
    | `UNWILLING_TO_PERFORM -> 53
    | `LOOP_DETECT -> 54
    | `NAMING_VIOLATION -> 64
    | `OBJECT_CLASS_VIOLATION -> 65
    | `NOT_ALLOWED_ON_NONLEAF -> 66
    | `NOT_ALLOWED_ON_RDN -> 67
    | `ALREADY_EXISTS -> 68
    | `NO_OBJECT_CLASS_MODS -> 69
    | `AFFECTS_MULTIPLE_DSAS -> 71
    | `OTHER -> 80
    | `SERVER_DOWN -> 80
    | `LOCAL_ERROR -> 80
    | `ENCODING_ERROR -> 80
    | `DECODING_ERROR -> 80
    | `TIMEOUT -> 80
    | `AUTH_UNKNOWN -> 80
    | `FILTER_ERROR -> 80
    | `USER_CANCELLED -> 80
    | `PARAM_ERROR -> 80
    | `NO_MEMORY -> 80
    | `CONNECT_ERROR -> 80
    | `NOT_SUPPORTED -> 80
    | `CONTROL_NOT_FOUND -> 80
    | `NO_RESULTS_RETURNED -> 80
    | `MORE_RESULTS_TO_RETURN -> 80
    | `CLIENT_LOOP -> 80
    | `REFERRAL_LIMIT_EXCEEDED -> 80
    | `UNKNOWN_ERROR i -> i

let decode_resultcode code =
  match code with
      0 -> `SUCCESS
    | 1 -> `OPERATIONS_ERROR
    | 2 -> `PROTOCOL_ERROR
    | 3 -> `TIMELIMIT_EXCEEDED
    | 4 -> `SIZELIMIT_EXCEEDED
    | 5 -> `COMPARE_FALSE
    | 6 -> `COMPARE_TRUE
    | 7 -> `AUTH_METHOD_NOT_SUPPORTED
    | 8 -> `STRONG_AUTH_REQUIRED
    | 10 -> `REFERRAL
    | 11 -> `ADMINLIMIT_EXCEEDED
    | 12 -> `UNAVAILABLE_CRITICAL_EXTENSION
    | 13 -> `CONFIDENTIALITY_REQUIRED
    | 14 -> `SASL_BIND_IN_PROGRESS
    | 16 -> `NO_SUCH_ATTRIBUTE
    | 17 -> `UNDEFINED_TYPE
    | 18 -> `INAPPROPRIATE_MATCHING
    | 19 -> `CONSTRAINT_VIOLATION
    | 20 -> `TYPE_OR_VALUE_EXISTS
    | 21 -> `INVALID_SYNTAX
    | 32 -> `NO_SUCH_OBJECT
    | 33 -> `ALIAS_PROBLEM
    | 34 -> `INVALID_DN_SYNTAX
    | 35 -> `IS_LEAF
    | 36 -> `ALIAS_DEREF_PROBLEM
    | 48 -> `INAPPROPRIATE_AUTH
    | 49 -> `INVALID_CREDENTIALS
    | 50 -> `INSUFFICIENT_ACCESS
    | 51 -> `BUSY
    | 52 -> `UNAVAILABLE
    | 53 -> `UNWILLING_TO_PERFORM
    | 54 -> `LOOP_DETECT
    | 64 -> `NAMING_VIOLATION
    | 65 -> `OBJECT_CLASS_VIOLATION
    | 66 -> `NOT_ALLOWED_ON_NONLEAF
    | 67 -> `NOT_ALLOWED_ON_RDN
    | 68 -> `ALREADY_EXISTS
    | 69 -> `NO_OBJECT_CLASS_MODS
    | 71 -> `AFFECTS_MULTIPLE_DSAS
    | 80 -> `OTHER
    | i ->  `UNKNOWN_ERROR i

let decode_control_type s =
  match s with
  | "1.2.840.113556.1.4.319" -> `Paged_results_control
  | x -> `Unknown_type x

let encode_control_type c =
  match c.control_details with
  | `Paged_results_control _ -> "1.2.840.113556.1.4.319"
  | _ -> raise (LDAP_Encoder "encode_ldapcontrol: unknown control type")

(* encode a standard sequence header *)
let encode_seq_hdr ?(cls=Universal) ?(tag=16) length =
  encode_ber_header
    {ber_class=cls;
     ber_tag=tag;
     ber_primitive=false;
     ber_length=Definite length}

let encode_ldapcontrol control =
  let en_type = encode_ber_octetstring (encode_control_type control) in
  let build_final_str hdr_len part_list =
    let en_ctrl_hdr = encode_seq_hdr ~cls:Universal ~tag:16 hdr_len in
    let body = String.concat "" part_list in
    String.concat "" [en_ctrl_hdr; body]
  in
  match control.control_details with
  | `Unknown_value c_val ->
    let header_len = (String.length en_type) + (String.length c_val) in
    build_final_str header_len [en_type; c_val]
  | `Paged_results_control ctrl_val ->
    let en_size = encode_ber_int32 (Int32.of_int ctrl_val.size) in
    let en_cookie = encode_ber_octetstring ctrl_val.cookie in
    let control_val_length = (String.length en_size) + (String.length en_cookie) in
    let control_val_hdr = encode_seq_hdr ~cls:Universal ~tag:16 control_val_length in
    let control_value = String.concat "" [control_val_hdr; en_size; en_cookie] in
    let control_w_hdr =
      encode_ber_octetstring ~cls:Universal ~tag:4 control_value
    in
    let header_len =
      (String.length en_type) + (String.length control_w_hdr)
    in
    build_final_str header_len [en_type; control_w_hdr]

let encode_ldapcontrol_list control_list =
  let all_encoded_ctrls = List.fold_left
    (fun str ctrl ->
      String.concat str [(encode_ldapcontrol ctrl)])
    ""
    control_list
  in
  let all_ctrls_header =
    encode_seq_hdr ~cls:Context_specific ~tag:0 ((String.length all_encoded_ctrls))
  in
  String.concat "" [all_ctrls_header; all_encoded_ctrls]

let decode_ldapcontrol rb =
  decode_ber_header rb >>= function
      {ber_class=Universal;ber_tag=16;ber_length=len} ->
        let rb = readbyte_of_ber_element len rb in
        decode_ber_octetstring rb >>= fun control_type_string ->
        let controlType = decode_control_type control_type_string in
        (* not handling criticality *)
          decode_ber_header rb >>= fun _ ->
          let criticality = false in
          let control_details =
            begin match controlType with
            | `Paged_results_control ->
              begin
              catch
                (fun () ->
                   decode_ber_header rb >>= fun _ ->
                   decode_ber_int32 rb >|= Int32.to_int  >>= fun size ->
                   decode_ber_octetstring rb >>= fun cookie ->
                   return (`Paged_results_control {size=size; cookie=cookie}))
                (function
                   | Readbyte_error End_of_stream -> return (`Unknown_value "")
                   | exn -> fail exn)
              end
            | `Unknown_type _ -> return (`Unknown_value "")
            end
        in
          control_details >|= fun control_details ->
          {criticality=criticality;control_details=control_details}
    | _ -> fail (LDAP_Decoder "decode_ldapcontrol: expected sequence")

let decode_ldapcontrols rb =
  catch begin fun () ->
    let rb = (* set the context to this control *)
      decode_ber_header rb >>= function
          {ber_class=Context_specific;ber_tag=0;ber_length=control_length} ->
            return (readbyte_of_ber_element control_length rb)
        | _ -> fail (LDAP_Decoder "decode_ldapcontrol: expected control (controls [0])")
    in
    let rec decode_ldapcontrols' ?(controls=[]) rb =
      catch
        (fun () ->
           (decode_ldapcontrol rb) >>= fun control ->
           (decode_ldapcontrols' ~controls:(control :: controls) rb))
        (function
           | Readbyte_error End_of_stream -> begin
              match controls with
                  [] -> return None
                | controls -> return (Some (List.rev controls) (* return them in order *))
             end
           | exn -> fail exn)
    in
      rb >>= decode_ldapcontrols'
  end
  begin function
    | Readbyte_error End_of_stream -> return None
    | exn -> fail exn
  end

let encode_components_of_ldapresult {result_code=resultcode;
                                     matched_dn=dn;error_message=msg;
                                     ldap_referral=refs} =
  let result_code = encode_ber_enum (Int32.of_int (encode_resultcode resultcode)) in
  let matched_dn = encode_ber_octetstring dn in
  let error_message = encode_ber_octetstring msg in
  let ldap_referral = (match refs with
                           Some refs ->
                             let buf = Buffer.create 100 in
                               List.iter
                                 (fun ref ->
                                    Buffer.add_string buf (encode_ber_octetstring ref))
                                 refs;
                               let hdr = Buffer.create 101 in
                                 Buffer.add_string hdr
                                   (encode_ber_header
                                      {ber_class=Context_specific;
                                       ber_tag=3;
                                       ber_primitive=false;
                                       ber_length=Definite (Buffer.length buf)});
                                 Buffer.add_buffer hdr buf;
                                 Some (Buffer.contents hdr)
                         | None -> None)
  in
  let buf = Buffer.create 100 in
    Buffer.add_string buf result_code;
    Buffer.add_string buf matched_dn;
    Buffer.add_string buf error_message;
    (match ldap_referral with
         Some s -> Buffer.add_string buf s
       | None -> ());
    Buffer.contents buf

let encode_ldapresult ?(cls=Universal) ?(tag=16) ldapresult =
  let components = encode_components_of_ldapresult ldapresult in
  let len = String.length components in
  let buf = Buffer.create (len + 20) in
    Buffer.add_string buf (encode_ber_header {ber_class=cls;
                                              ber_tag=tag;
                                              ber_primitive=false;
                                              ber_length=(Definite len)});
    Buffer.add_string buf components;
    Buffer.contents buf

let decode_components_of_ldapresult rb =
  decode_ber_enum rb >>= fun resultCodeval ->
  decode_ber_octetstring rb >>= fun matched_dn ->
  decode_ber_octetstring rb >>= fun error_message ->
  let referrals =
    catch
      (fun () ->
        (decode_ber_header ~peek:true rb >>= function
           {ber_class=Context_specific;ber_tag=3;ber_length=referral_length} ->
             (decode_ber_header rb) >>= fun _ ->
             let rb = readbyte_of_ber_element referral_length rb in
               (decode_berval_list decode_ber_octetstring rb >>= function
                    [] -> return None
                  | lst -> return (Some lst))
         | _ -> return None))
      (function
         | Readbyte_error End_of_stream -> return None
         | exn -> fail exn)
  in
    referrals >>= fun referrals ->
    return
      {result_code=(decode_resultcode (Int32.to_int resultCodeval));
       matched_dn=matched_dn;
       error_message=error_message;
       ldap_referral=referrals}

let decode_ldapresult rb =
  let rb = (* set context to this result only *)
    (decode_ber_header rb >>= function
         {ber_class=Universal;ber_tag=16;ber_length=result_length} ->
           return (readbyte_of_ber_element result_length rb)
       | _ -> fail (LDAP_Decoder "decode_ldapresult: expected ldapresult (sequence)"))
  in
    rb >>= decode_components_of_ldapresult

let encode_bindrequest {bind_version=ver;bind_name=dn;bind_authentication=auth} =
  let buf = Buffer.create 100 in
  let version = encode_ber_int32 (Int32.of_int ver) in
  let dn = encode_ber_octetstring dn in
  let auth = (match auth with
                  Simple pwd -> encode_ber_octetstring ~cls:Context_specific ~tag:0 pwd
                | Sasl {sasl_mechanism=mech;sasl_credentials=cred} ->
                    let buf = Buffer.create 10 in
                    let mech = encode_ber_octetstring mech in
                    let cred = (match cred with
                                    Some cred -> Some (encode_ber_octetstring cred)
                                  | None -> None)
                    in
                    let hdr = encode_seq_hdr ~cls:Context_specific ~tag:3
                                ((String.length mech) +
                                 (match cred with
                                      Some cred -> String.length cred
                                    | None -> 0))
                    in
                      Buffer.add_string buf hdr;
                      Buffer.add_string buf mech;
                      (match cred with
                           Some cred -> Buffer.add_string buf cred
                         | None -> ());
                      Buffer.contents buf)
  in
  let hdr =
    (encode_ber_header
       {ber_class=Application;
        ber_tag=0;
        ber_primitive=false;
        ber_length=Definite ((String.length version) +
                             (String.length dn) +
                             (String.length auth))})
  in
    Buffer.add_string buf hdr;
    Buffer.add_string buf version;
    Buffer.add_string buf dn;
    Buffer.add_string buf auth;
    Buffer.contents buf

let decode_bindrequest rb =
  decode_ber_int32 rb >>= fun version ->
  decode_ber_octetstring rb >>= fun dn ->
  let cred =
    (decode_ber_header rb >>= function
         {ber_class=Context_specific;ber_tag=0;ber_length=cred_length} -> (* simple *)
           (read_contents rb cred_length) >>= fun contents ->
           (decode_ber_octetstring ~contents:(Some contents) rb) >|=
           fun x -> Simple x
       | {ber_class=Context_specific;ber_tag=3;ber_length=cred_length} -> (* sasl *)
           let rb = readbyte_of_ber_element cred_length rb in
           decode_ber_octetstring rb >>= fun sasl_mech ->
           let sasl_cred = catch
                             (fun () ->
                                (decode_ber_octetstring rb) >|=
                                fun x -> Some x)
                             (function
                                | Readbyte_error End_of_stream -> return None
                                | exn -> fail exn)
           in
             sasl_cred >>= fun sasl_cred ->
             return (Sasl {sasl_mechanism=sasl_mech;sasl_credentials=sasl_cred})
       | _ -> fail (LDAP_Decoder "decode_bindrequest: unknown authentication method"))
  in
    cred >|= fun cred ->
    Bind_request
      {bind_version=Int32.to_int version;
       bind_name=dn;
       bind_authentication=cred}

let encode_bindresponse {bind_result=result;bind_serverSaslCredentials=saslcred} =
  let encoded_result = encode_components_of_ldapresult result in
  let encoded_saslcred = match saslcred with
    | Some s -> Some (encode_ber_octetstring ~cls:Context_specific ~tag:7 s)
    | None -> None
  in
  let len = (String.length encoded_result) +
            (match encoded_saslcred with
                 Some s -> (String.length s)
               | None -> 0)
  in
  let buf = Buffer.create (len + 20) in
    Buffer.add_string buf
      (encode_ber_header {ber_class=Application;
                          ber_tag=1;ber_primitive=false;
                          ber_length=Definite len});
    Buffer.add_string buf encoded_result;
    (match encoded_saslcred with
         Some s -> Buffer.add_string buf s
       | None -> ());
    Buffer.contents buf

let decode_bindresponse rb =
  decode_components_of_ldapresult rb >>= fun result ->
  let saslcred = catch
                   (fun () -> (decode_ber_octetstring rb) >|= fun x -> Some x)
                   (function Readbyte_error End_of_stream -> return None
                      | exn -> fail exn)
  in
    saslcred >|= fun saslcred ->
    Bind_response
       {bind_result=result;
        bind_serverSaslCredentials=saslcred}

let decode_unbindrequest rb =
  (* some clients do not properly encode the length octets, which will cause decoding
     of null values to fail. In short, it is never OK to omit completely the length
     octets, however some clients (namely openldap) do it anyway *)
  catch
    (fun () -> (decode_ber_null rb) >>= fun _ -> return ())
    (function Readbyte_error End_of_stream -> return ()
       | exn -> fail exn)
  >>= fun _ ->
  return Unbind_request

let encode_unbindrequest () = encode_ber_null ()

(* not really a sequence *)
let decode_attributevalueassertion rb =
  decode_ber_octetstring rb >>= fun attributeDesc ->
  decode_ber_octetstring rb >>= fun assertionValue ->
    return {attributeDesc=attributeDesc; assertionValue=assertionValue}

let encode_substringfilter {attrtype=attr;
                            substrings={substr_initial=initial;
                                        substr_any=any;substr_final=final}} =
  let encode_component ctype vals =
    match vals with
        [] -> ""
      | vals ->
          let tag =
            match ctype with
                `INITIAL -> 0
              | `ANY -> 1
              | `FINAL -> 2
          in
          let buf =
            Buffer.create
              (List.fold_left
                 (fun s v -> s + (String.length v) + 3)
                 0 vals)
          in
            List.iter
              (fun v ->
                 Buffer.add_string buf
                   (encode_ber_octetstring ~cls:Context_specific ~tag v))
              vals;
            Buffer.contents buf
  in
  let e_attr = encode_ber_octetstring attr in
  let e_initial = encode_component `INITIAL initial in
  let e_any = encode_component `ANY any in
  let e_final = encode_component `FINAL final in
  let component_len = (String.length e_initial) + (String.length e_any) + (String.length e_final) in
  let component_buf = Buffer.create (component_len + 3) in
    Buffer.add_string component_buf
      (encode_ber_header
         {ber_class=Universal;ber_tag=16;ber_primitive=false;
          ber_length=(Definite component_len)});
    Buffer.add_string component_buf e_initial;
    Buffer.add_string component_buf e_any;
    Buffer.add_string component_buf e_final;
    let len = ((Buffer.length component_buf) + (String.length e_attr)) in
    let buf = Buffer.create (len + 3) in
      Buffer.add_string buf
        (encode_ber_header
           {ber_class=Context_specific;ber_tag=4;ber_primitive=false;
            ber_length=(Definite len)});
      Buffer.add_string buf e_attr;
      Buffer.add_buffer buf component_buf;
      Buffer.contents buf

let decode_substringfilter rb =
  let rec decode_substring_components skel rb =
    catch begin fun () ->
      decode_ber_header ~peek:true rb >>= function
          {ber_class=Context_specific;ber_tag=0} ->
            (decode_ber_octetstring ~cls:Context_specific ~tag:0 rb) >>= fun initial ->
            decode_substring_components
              {skel with substr_initial=(initial :: skel.substr_initial)}
              rb
        | {ber_class=Context_specific;ber_tag=1} ->
            (decode_ber_octetstring ~cls:Context_specific ~tag:1 rb) >>= fun any ->
            decode_substring_components
              {skel with substr_any=(any :: skel.substr_any)}
              rb
        | {ber_class=Context_specific;ber_tag=2} ->
            (decode_ber_octetstring ~cls:Context_specific ~tag:2 rb) >>= fun final ->
            decode_substring_components
              {skel with substr_final=(final :: skel.substr_final)}
              rb
        | _ -> fail (LDAP_Decoder "decode_substringfilter: invalid substring component")
    end
    (function Readbyte_error End_of_stream -> return skel
       | exn -> fail exn)
  in
  decode_ber_octetstring rb >>= fun attrtype ->
  let components =
    (decode_ber_header rb >>= function
         {ber_class=Universal;ber_tag=16;ber_length=len} ->
           let rb = readbyte_of_ber_element len rb in
           let skel = {substr_initial=[];substr_any=[];substr_final=[]} in
           decode_substring_components skel rb >>= fun result ->
             if result = skel then
               fail (LDAP_Decoder "decode_substringfilter: invalid substring filter")
             else
               return result
       | _ -> fail (LDAP_Decoder "decode_substringfilter: expected sequence of choice"))
  in
    components >>= fun components ->
    return {attrtype=attrtype; substrings=components}

let encode_matchingruleassertion {matchingRule=mrule;ruletype=mruletype;
                                  matchValue=valu;dnAttributes=dnattrs} =
  let olen s = match s with Some s -> String.length s | None -> 0 in
  let oadd buf encoded =
    (match encoded with
         Some e -> Buffer.add_string buf e
       | None -> ())
  in
  let oencode tag valu =
        match valu with
        Some s -> Some (encode_ber_octetstring ~cls:Context_specific ~tag:tag s)
      | None -> None
  in
  let e_mrule = oencode 1 mrule in
  let e_mruletype = oencode 2 mruletype in
  let e_valu = encode_ber_octetstring ~cls:Context_specific ~tag:3 valu in
  let e_dnattrs = encode_ber_bool ~cls:Context_specific ~tag:4 dnattrs in
  let len = (olen e_mrule) + (olen e_mruletype) + (String.length e_valu) +
            (String.length e_dnattrs)
  in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Context_specific;ber_tag=9;
          ber_primitive=false;ber_length=(Definite len)});
    oadd buf e_mrule;
    oadd buf e_mruletype;
    Buffer.add_string buf e_valu;
    Buffer.add_string buf e_dnattrs;
    Buffer.contents buf

let decode_matchingruleassertion rb =
  let matchingrule =
    (decode_ber_header ~peek:true rb >>= function
         {ber_class=Context_specific;ber_tag=0;ber_length=len} ->
           (decode_ber_octetstring ~cls:Context_specific ~tag:1 rb) >|=
           fun x -> Some x
       | _ -> return None)
  in matchingrule >>= fun matchingrule ->
  let ruletype =
    (decode_ber_header ~peek:true rb >>= function
         {ber_class=Context_specific;ber_tag=1;ber_length=len} ->
           (decode_ber_octetstring ~cls:Context_specific ~tag:2 rb) >|=
           fun x -> Some x
       | _ -> return None)
  in ruletype >>= fun ruletype ->
  decode_ber_octetstring rb >>= fun matchvalue ->
  let dnattributes = catch
                       (fun () -> decode_ber_bool rb)
                       (function Readbyte_error End_of_stream -> return false
                          | exn -> fail exn)
  in
    dnattributes >|= fun dnattributes ->
    {matchingRule=matchingrule;
     ruletype=ruletype;
     matchValue=matchvalue;
     dnAttributes=dnattributes}

let rec encode_ldapfilter filter =
  let encode_complex lst hdr =
    let encoded_lst = encode_berval_list encode_ldapfilter lst in
    let len = String.length encoded_lst in
    let buf = Buffer.create (len + 10) in
      Buffer.add_string buf
        (encode_ber_header {hdr with ber_length=(Definite len)});
      Buffer.add_string buf encoded_lst;
      Buffer.contents buf
  in
  let encode_simple attr valu hdr =
    let e_attr = encode_ber_octetstring attr in
    let e_valu = encode_ber_octetstring valu in
    let len = (String.length e_attr) + (String.length e_valu) in
    let buf = Buffer.create (len + 10) in
      Buffer.add_string buf
        (encode_ber_header {hdr with ber_length=(Definite len)});
      Buffer.add_string buf e_attr;
      Buffer.add_string buf e_valu;
      Buffer.contents buf
  in
  let hdr = {ber_class=Context_specific;ber_tag=0;
                 ber_primitive=false;ber_length=Definite 0}
  in
    match filter with
        `And lst -> encode_complex lst hdr
      | `Or lst -> encode_complex lst {hdr with ber_tag=1}
      | `Not f -> encode_complex [f] {hdr with ber_tag=2}
      | `EqualityMatch {attributeDesc=attr;assertionValue=valu} ->
          encode_simple attr valu {hdr with ber_tag=3}
      | `Substrings substrs -> encode_substringfilter substrs
      | `GreaterOrEqual {attributeDesc=attr;assertionValue=valu} ->
          encode_simple attr valu {hdr with ber_tag=5}
      | `LessOrEqual {attributeDesc=attr;assertionValue=valu} ->
          encode_simple attr valu {hdr with ber_tag=6}
      | `Present attr -> encode_ber_octetstring ~cls:Context_specific ~tag:7 attr
      | `ApproxMatch {attributeDesc=attr;assertionValue=valu} ->
          encode_simple attr valu {hdr with ber_tag=8}
      | `ExtensibleMatch extn -> encode_matchingruleassertion extn

let rec decode_ldapfilter rb =
  decode_ber_header rb >>= function
      {ber_class=Context_specific;ber_tag=0;ber_length=len} -> (* and *)
        let rb = readbyte_of_ber_element len rb in
          (decode_berval_list decode_ldapfilter rb) >|= fun x -> `And x
    | {ber_class=Context_specific;ber_tag=1;ber_length=len} -> (* or *)
        let rb = readbyte_of_ber_element len rb in
          (decode_berval_list decode_ldapfilter rb) >|= fun x -> `Or  x
    | {ber_class=Context_specific;ber_tag=2;ber_length=len} -> (* not *)
        (decode_ldapfilter rb) >|= fun x -> `Not x
    | {ber_class=Context_specific;ber_tag=3;ber_length=len} -> (* equality match *)
        (decode_attributevalueassertion rb) >|= fun x -> `EqualityMatch x
    | {ber_class=Context_specific;ber_tag=4;ber_length=len} -> (* substring match *)
        (decode_substringfilter rb) >|= fun x -> `Substrings x
    | {ber_class=Context_specific;ber_tag=5;ber_length=len} -> (* greater than or equal *)
        (decode_attributevalueassertion rb) >|= fun x -> `GreaterOrEqual x
    | {ber_class=Context_specific;ber_tag=6;ber_length=len} -> (* less than or equal *)
        (decode_attributevalueassertion rb) >|= fun x -> `LessOrEqual x
    | {ber_class=Context_specific;ber_tag=7;ber_length=len} -> (* present *)
        (read_contents rb len) >>= fun contents ->
          (decode_ber_octetstring ~contents:(Some contents) rb) >|= fun x -> `Present x
    | {ber_class=Context_specific;ber_tag=8;ber_length=len} -> (* approx *)
        (decode_attributevalueassertion rb) >|= fun x -> `ApproxMatch x
    | {ber_class=Context_specific;ber_tag=9;ber_length=len} -> (* extensible match *)
        (decode_matchingruleassertion rb) >|= fun x -> `ExtensibleMatch x
    | _ -> fail (LDAP_Decoder "decode_filter: expected filter part")

let encode_attributedescriptionlist attrs =
  let e_attrs = encode_berval_list encode_ber_octetstring attrs in
  let len = String.length e_attrs in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Universal;ber_tag=16;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf e_attrs;
    Buffer.contents buf

let decode_attributedescriptionlist rb =
  decode_ber_header rb >>= function
      {ber_class=Universal;ber_tag=16} ->
        decode_berval_list decode_ber_octetstring rb
    | _ -> fail (LDAP_Decoder "decode_attributedescriptionlist: expected sequence")

let encode_searchrequest {baseObject=base;scope=scope;
                          derefAliases=deref;sizeLimit=sizelimit;
                          timeLimit=timelimit;typesOnly=typesonly;
                          filter=filter;s_attributes=attributes} =
  let e_base = encode_ber_octetstring base in
  let e_scope =
    encode_ber_enum
      (match scope with
           `BASE -> 0l
         | `ONELEVEL -> 1l
         | `SUBTREE -> 2l)
  in
  let e_deref =
    encode_ber_enum
      (match deref with
           `NEVERDEREFALIASES -> 0l
         | `DEREFINSEARCHING -> 1l
         | `DEREFFINDINGBASE -> 2l
         | `DEREFALWAYS -> 3l)
  in
  let e_sizelimit = encode_ber_int32 sizelimit in
  let e_timelimit = encode_ber_int32 timelimit in
  let e_typesonly = encode_ber_bool typesonly in
  let e_filter = encode_ldapfilter filter in
  let e_attributes = encode_attributedescriptionlist attributes in
  let len = (String.length e_base) + (String.length e_scope) +
            (String.length e_deref) + (String.length e_sizelimit) +
            (String.length e_timelimit) + (String.length e_typesonly) +
            (String.length e_filter) + (String.length e_attributes)
  in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=3;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf e_base;
    Buffer.add_string buf e_scope;
    Buffer.add_string buf e_deref;
    Buffer.add_string buf e_sizelimit;
    Buffer.add_string buf e_timelimit;
    Buffer.add_string buf e_typesonly;
    Buffer.add_string buf e_filter;
    Buffer.add_string buf e_attributes;
    Buffer.contents buf

let decode_searchrequest rb =
  decode_ber_octetstring rb >>= fun base ->
  let scope = (decode_ber_enum rb >>= function
                   0l -> return `BASE
                 | 1l -> return `ONELEVEL
                 | 2l -> return `SUBTREE
                 | _  -> fail (LDAP_Decoder "decode_searchrequest: invalid scope"))
  in scope >>= fun scope ->
  let deref = (decode_ber_enum rb >>= function
                   0l -> return `NEVERDEREFALIASES
                 | 1l -> return `DEREFINSEARCHING
                 | 2l -> return `DEREFFINDINGBASE
                 | 3l -> return `DEREFALWAYS
                 | _  -> fail (LDAP_Decoder "decode_searchrequest: invalid deref policy"))
  in deref >>= fun deref ->
  decode_ber_int32 rb >>= fun sizelimit ->
  decode_ber_int32 rb >>= fun timelimit ->
  decode_ber_bool rb >>= fun typesonly ->
  decode_ldapfilter rb >>= fun filter ->
  decode_attributedescriptionlist rb >>= fun attributes ->
    return begin
      Search_request
        {baseObject=base;
         scope=scope;
         derefAliases=deref;
         sizeLimit=sizelimit;
         timeLimit=timelimit;
         typesOnly=typesonly;
         filter=filter;
         s_attributes=attributes}
    end

let encode_attribute {attr_type=attrtype;attr_vals=attrvals} =
  let e_attrtype = encode_ber_octetstring attrtype in
  let e_attrvals =
    let vals = encode_berval_list encode_ber_octetstring attrvals in
    let len = String.length vals in
    let buf = Buffer.create (len + 10) in
      Buffer.add_string buf
        (encode_ber_header
           {ber_class=Universal;ber_tag=17;
            ber_primitive=false;ber_length=(Definite len)});
      Buffer.add_string buf vals;
      Buffer.contents buf
  in
  let len = (String.length e_attrtype) + (String.length e_attrvals) in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Universal;ber_tag=16;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf e_attrtype;
    Buffer.add_string buf e_attrvals;
    Buffer.contents buf

let decode_attribute rb =
  decode_ber_header rb >>= function
      {ber_class=Universal;ber_tag=16;ber_length=len} ->
        let rb = readbyte_of_ber_element len rb in
        decode_ber_octetstring rb >>= fun attrtype ->
        let attrvals =
          decode_ber_header rb >>= function
              {ber_class=Universal;ber_tag=17} ->
                decode_berval_list decode_ber_octetstring rb
            | _ -> fail (LDAP_Decoder "decode_attribute: expected set")
        in
          attrvals >|= fun attrvals ->
          {attr_type=attrtype;attr_vals=attrvals}
    | _ -> fail (LDAP_Decoder "decode_attributes: expected sequence")

(* also used to encode addrequest. Forgive the naming conventions, trying to
   follow the ASN.1 closely, but not copy some of its problems at the same time.
   They have a few seperate implementations of entry,
   all the same encoding, but with different names, and different ASN.1 code! *)
let encode_searchresultentry ?(tag=4) {sr_dn=dn;sr_attributes=attributes} =
  let e_dn = encode_ber_octetstring dn in
  let e_attributes =
    let valu = encode_berval_list encode_attribute attributes in
    let len = String.length valu in
    let buf = Buffer.create (len + 10) in
      Buffer.add_string buf
        (encode_ber_header
           {ber_class=Universal;ber_tag=16;
            ber_primitive=false;ber_length=(Definite len)});
      Buffer.add_string buf valu;
      Buffer.contents buf
  in
  let len = (String.length e_dn) + (String.length e_attributes) in
  let buf = Buffer.create 50 in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=tag;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf e_dn;
    Buffer.add_string buf e_attributes;
    Buffer.contents buf

let decode_searchresultentry rb =
  decode_ber_octetstring rb >>= fun dn ->
  let attributes =
    decode_ber_header rb >>= function
        {ber_class=Universal;ber_tag=16;ber_length=len} ->
          let rb = readbyte_of_ber_element len rb in
            decode_berval_list decode_attribute rb
      | _ -> fail (LDAP_Decoder "decode_searchresultentry: expected squenece")
  in
    attributes >|= fun attributes ->
    Search_result_entry
      {sr_dn=dn;sr_attributes=attributes}

let encode_searchresultdone = encode_ldapresult ~cls:Application ~tag:5

let decode_searchresultdone rb =
  (decode_components_of_ldapresult rb) >|= fun x -> Search_result_done x

let encode_searchresultreference srf =
  let refs = encode_berval_list encode_ber_octetstring srf in
  let len = String.length refs in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=19;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf refs;
    Buffer.contents buf

let decode_searchresultreference rb =
  (decode_berval_list decode_ber_octetstring rb) >|= fun x -> Search_result_reference x

let encode_modification {mod_op=op;mod_value=attr} =
  let e_op = encode_ber_enum
               (match op with
                    `ADD -> 0l
                  | `DELETE -> 1l
                  | `REPLACE -> 2l)
  in
  let e_attr = encode_attribute attr in
  let len = (String.length e_op) + (String.length e_attr) in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Universal;ber_tag=16;ber_primitive=false;
          ber_length=(Definite len)});
    Buffer.add_string buf e_op;
    Buffer.add_string buf e_attr;
    Buffer.contents buf

let decode_modification rb =
  decode_ber_header rb >>= function
      {ber_class=Universal;ber_tag=16;ber_length=len} -> (* sequence is specified *)
        let rb = readbyte_of_ber_element len rb in
        let op = (decode_ber_enum rb >>= function
                      0l -> return `ADD
                    | 1l -> return `DELETE
                    | 2l -> return `REPLACE
                    | _  -> fail (LDAP_Decoder "decode_modification: unknown operation"))
        in op >>= fun op ->
        decode_attribute rb >>= fun attr ->
          return {mod_op=op;mod_value=attr}
    | {ber_class=cls;ber_tag=tag;ber_length=len} ->
        fail (LDAP_Decoder
                 ("decode_modification: expected sequence, or enum, " ^
                    ("tag: " ^ (string_of_int tag))))

let encode_modifyrequest {mod_dn=dn;modification=mods} =
  let e_dn = encode_ber_octetstring dn in
  let e_mods =
    let vals = encode_berval_list encode_modification mods in
    let len = String.length vals in
    let buf = Buffer.create (len + 10) in
      Buffer.add_string buf
        (encode_ber_header
           {ber_class=Universal;ber_tag=16;ber_primitive=false;
            ber_length=(Definite len)});
      Buffer.add_string buf vals;
      Buffer.contents buf
  in
  let len = (String.length e_dn) + (String.length e_mods) in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=6;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf e_dn;
    Buffer.add_string buf e_mods;
    Buffer.contents buf

let decode_modifyrequest rb =
  decode_ber_octetstring rb >>= fun dn ->
  let mods =
    decode_ber_header rb >>= function
        {ber_class=Universal;ber_tag=16;ber_length=len} ->
          let rb = readbyte_of_ber_element len rb in
            decode_berval_list decode_modification rb
      | _ -> fail (LDAP_Decoder "decode_modifyrequest: expected sequence")
  in
    mods >|= fun mods ->
    Modify_request {mod_dn=dn;modification=mods}

let encode_modifyresponse = encode_ldapresult ~cls:Application ~tag:7

let decode_modifyresponse rb =
  (decode_components_of_ldapresult rb) >|= fun x -> Modify_response x

(* the types from search are reused. I refuse to duplicate them
   each type countless times like the ASN.1 specification does *)
let encode_addrequest = encode_searchresultentry ~tag:8
let decode_addrequest rb =
  decode_searchresultentry rb >>= fun res ->
    match res with
        Search_result_entry res -> return (Add_request res)
      | _ -> fail (LDAP_Decoder "decode_addrequest: invalid addrequest")

let encode_addresponse = encode_ldapresult ~cls:Application ~tag:9
let decode_addresponse rb =
  (decode_components_of_ldapresult rb) >|= fun x -> Add_response x

let encode_deleterequest req =
  encode_ber_octetstring ~cls:Application ~tag:10 req

let decode_deleterequest len rb =
  (read_contents rb len) >>= fun contents ->
  (decode_ber_octetstring ~contents:(Some contents) rb) >|= fun x -> Delete_request x

let encode_deleteresponse = encode_ldapresult ~cls:Application ~tag:11
let decode_deleteresponse rb =
  (decode_components_of_ldapresult rb) >|= fun x -> Delete_response x

let encode_modifydnrequest {modn_dn=dn;modn_newrdn=newrdn;
                            modn_deleteoldrdn=deleteold;
                            modn_newSuperior=newsup} =
  let e_dn = encode_ber_octetstring dn in
  let e_newrdn = encode_ber_octetstring newrdn in
  let e_deleteold = encode_ber_bool deleteold in
  let e_newsup = (match newsup with
                      Some s -> Some (encode_ber_octetstring s)
                    | None -> None)
  in
  let len = (String.length e_dn) + (String.length e_newrdn) +
            (String.length e_deleteold) + (match e_newsup with
                                               Some s -> String.length s
                                             | None -> 0)
  in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=12;ber_primitive=false;
          ber_length=(Definite len)});
    Buffer.add_string buf e_dn;
    Buffer.add_string buf e_newrdn;
    Buffer.add_string buf e_deleteold;
    (match e_newsup with
         Some s -> Buffer.add_string buf s
       | None -> ());
    Buffer.contents buf

let decode_modifydnrequest rb =
  decode_ber_octetstring rb >>= fun dn ->
  decode_ber_octetstring rb >>= fun newrdn ->
  decode_ber_bool rb >>= fun deleteoldrdn ->
  let newsup = (catch
                  (fun () ->
                     decode_ber_octetstring ~cls:Context_specific ~tag:0 rb >|=
                     fun x -> Some x)
                  (function Readbyte_error End_of_stream -> return None
                     | exn -> fail exn))
  in
    newsup >|= fun newsup ->
    Modify_dn_request
      {modn_dn=dn;modn_newrdn=newrdn;
       modn_deleteoldrdn=deleteoldrdn;
       modn_newSuperior=newsup}

let encode_modifydnresponse = encode_ldapresult ~cls:Application ~tag:13

let decode_modifydnresponse rb =
  (decode_components_of_ldapresult rb) >|= fun x -> Modify_dn_response x

let encode_comparerequest {cmp_dn=dn;
                           cmp_ava={attributeDesc=attr;assertionValue=valu}} =
  let e_dn = encode_ber_octetstring dn in
  let e_attr = encode_ber_octetstring attr in
  let e_valu = encode_ber_octetstring valu in
  let len = (String.length e_dn) + (String.length e_attr) +
            (String.length e_valu)
  in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=14;
          ber_primitive=false;ber_length=(Definite len)});
    Buffer.add_string buf e_dn;
    Buffer.add_string buf e_attr;
    Buffer.add_string buf e_valu;
    Buffer.contents buf

let decode_comparerequest rb =
  decode_ber_octetstring rb >>= fun dn ->
  decode_ber_octetstring rb >>= fun attr ->
  decode_ber_octetstring rb >|= fun valu ->
    Compare_request
      {cmp_dn=dn;cmp_ava={attributeDesc=attr;assertionValue=valu}}

let encode_compareresponse = encode_ldapresult ~cls:Application ~tag:15

let decode_compareresponse rb =
  (decode_components_of_ldapresult rb) >|= fun x -> Compare_response x

let encode_abandonrequest msgid =
  let e_msgid = encode_ber_int32 msgid in
  let len = String.length e_msgid in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=16;ber_primitive=false;
          ber_length=(Definite len)});
    Buffer.add_string buf e_msgid;
    Buffer.contents buf

let decode_abandonrequest rb =
  (decode_ber_int32 rb) >|= fun x -> Abandon_request x

let encode_extendedrequest {ext_requestName=reqname;ext_requestValue=reqval} =
  let e_reqname = encode_ber_octetstring reqname in
  let e_reqval = (match reqval with
                      Some s -> Some (encode_ber_octetstring s)
                    | None -> None)
  in
  let len = (String.length e_reqname) + (match e_reqval with
                                             Some s -> String.length s
                                           | None -> 0)
  in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=23;ber_primitive=false;
          ber_length=(Definite len)});
    Buffer.add_string buf e_reqname;
    (match e_reqval with
         Some s -> Buffer.add_string buf s
       | None -> ());
    Buffer.contents buf

let decode_extendedrequest rb =
  decode_ber_octetstring ~cls:Context_specific ~tag:0 rb >>= fun reqname ->
  let reqval =
    catch
      (fun () -> decode_ber_octetstring ~cls:Context_specific ~tag:1 rb >|=
                 fun x -> Some x)

      (function Readbyte_error End_of_stream -> return None | exn -> fail exn)
  in
    reqval >|= fun reqval ->
    Extended_request
      {ext_requestName=reqname;ext_requestValue=reqval}

let encode_extendedresponse {ext_result=result;ext_responseName=resname;ext_response=res} =
  let e_result = encode_components_of_ldapresult result in
  let e_resname = (match resname with
                       Some s -> Some (encode_ber_octetstring s)
                     | None -> None)
  in
  let e_res = (match res with
                   Some s -> Some (encode_ber_octetstring s)
                 | None -> None)
  in
  let len = (String.length e_result) +
            (match e_resname with
                 Some s -> String.length s
               | None -> 0) +
            (match e_res with
                 Some s -> String.length s
               | None -> 0)
  in
  let buf = Buffer.create (len + 10) in
    Buffer.add_string buf
      (encode_ber_header
         {ber_class=Application;ber_tag=24;ber_primitive=false;
          ber_length=(Definite len)});
    Buffer.add_string buf e_result;
    (match e_resname with
         Some s -> Buffer.add_string buf s
       | None -> ());
    (match e_res with
         Some s -> Buffer.add_string buf s
       | None -> ());
    Buffer.contents buf

let decode_extendedresponse rb =
  decode_components_of_ldapresult rb >>= fun result ->
  let responsename = ref None in
  let response = ref None in
    (catch
       (fun () ->
          (decode_ber_octetstring ~cls:Context_specific ~tag:10 rb) >>= fun x ->
          responsename := Some x;
          (decode_ber_octetstring ~cls:Context_specific ~tag:11 rb) >>= fun x ->
          response := Some x;
          return ())
       (function Readbyte_error End_of_stream -> return () | exn -> fail exn)) >|= fun () ->
    Extended_response
      {ext_result=result;
       ext_responseName=(!responsename);
       ext_response=(!response)}

let encode_ldapmessage {messageID=msgid;protocolOp=protocol_op;controls=controls} =
  let encoded_op =
    match protocol_op with
        Bind_request br -> encode_bindrequest br
      | Bind_response br -> encode_bindresponse br
      | Unbind_request -> encode_unbindrequest ()
      | Search_request sr -> encode_searchrequest sr
      | Search_result_entry sre -> encode_searchresultentry sre
      | Search_result_done srd -> encode_searchresultdone srd
      | Search_result_reference a -> encode_searchresultreference a
      | Modify_request mreq -> encode_modifyrequest mreq
      | Modify_response res -> encode_modifyresponse res
      | Add_request sre -> encode_addrequest sre
      | Add_response res -> encode_addresponse res
      | Delete_request req -> encode_deleterequest req
      | Delete_response res -> encode_deleteresponse res
      | Modify_dn_request req -> encode_modifydnrequest req
      | Modify_dn_response res -> encode_modifydnresponse res
      | Compare_request req -> encode_comparerequest req
      | Compare_response res -> encode_compareresponse res
      | Abandon_request req -> encode_abandonrequest req
      | Extended_request req -> encode_extendedrequest req
      | Extended_response res -> encode_extendedresponse res
  in
  match controls with
  | Some ctrl_lst ->
    let en_ctrl_lst = encode_ldapcontrol_list ctrl_lst in
    let buf =
      Buffer.create ((String.length encoded_op) + 20 + (String.length en_ctrl_lst))
    in
    let msgid = encode_ber_int32 msgid in
      Buffer.add_string buf (encode_seq_hdr (
        (String.length encoded_op) +
        (String.length msgid) +
        (String.length en_ctrl_lst)));
      Buffer.add_string buf msgid;
      Buffer.add_string buf encoded_op;
      Buffer.add_string buf en_ctrl_lst;
      Buffer.contents buf
  | None ->
  let buf = Buffer.create ((String.length encoded_op) + 20) in
  let msgid = encode_ber_int32 msgid in
    Buffer.add_string buf
      (encode_seq_hdr ((String.length encoded_op) + (String.length msgid)));
    Buffer.add_string buf msgid;
    Buffer.add_string buf encoded_op;
    Buffer.contents buf

let decode_ldapmessage rb =
  decode_ber_header rb >>= function
      {ber_class=Universal;ber_tag=16;ber_length=total_length} ->
        (* set up our context to be this message *)
        let rb = readbyte_of_ber_element total_length rb in
        decode_ber_int32 rb >>= fun messageid ->
        let protocol_op =
          decode_ber_header rb >>= function
              {ber_class=Application;ber_tag=0;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_bindrequest rb
            | {ber_class=Application;ber_tag=1;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_bindresponse rb
            | {ber_class=Application;ber_tag=2;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_unbindrequest rb
            | {ber_class=Application;ber_tag=3;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_searchrequest rb
            | {ber_class=Application;ber_tag=4;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_searchresultentry rb
            | {ber_class=Application;ber_tag=5;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_searchresultdone rb
            | {ber_class=Application;ber_tag=19;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_searchresultreference rb
            | {ber_class=Application;ber_tag=6;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_modifyrequest rb
            | {ber_class=Application;ber_tag=7;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_modifyresponse rb
            | {ber_class=Application;ber_tag=8;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_addrequest rb
            | {ber_class=Application;ber_tag=9;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_addresponse rb
            | {ber_class=Application;ber_tag=10;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_deleterequest len rb
            | {ber_class=Application;ber_tag=11;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_deleteresponse rb
            | {ber_class=Application;ber_tag=12;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_modifydnrequest rb
            | {ber_class=Application;ber_tag=13;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_modifydnresponse rb
            | {ber_class=Application;ber_tag=14;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_comparerequest rb
            | {ber_class=Application;ber_tag=15;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_compareresponse rb
            | {ber_class=Application;ber_tag=16;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_abandonrequest rb
            | {ber_class=Application;ber_tag=23;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_extendedrequest rb
            | {ber_class=Application;ber_tag=24;ber_length=len} ->
                let rb = readbyte_of_ber_element len rb in
                  decode_extendedresponse rb
            | _ -> fail (LDAP_Decoder "protocol error")
        in protocol_op >>= fun protocol_op ->
        decode_ldapcontrols rb >|= fun controls ->
          {messageID=messageid;protocolOp=protocol_op;controls=controls}
    | _ -> fail (LDAP_Decoder "decode_ldapmessage: expected sequence")

end
