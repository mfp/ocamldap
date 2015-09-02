module Make (M : Ldap_types.Monad) = struct

open M
let (>>=) = bind
let (>|=) t f = bind t (fun x -> return (f x))

module Ldap_ooclient = Ldap_ooclient.Make(M)
open Ldap_ooclient
open Ldap_types

(* ldap mutexes *)
exception Ldap_mutex of string * exn

class type mutex_t =
object
  method lock: unit M.t
  method unlock: unit M.t
end

class type object_lock_table_t =
object
  method lock: dn -> unit M.t
  method unlock: dn -> unit M.t
end

let addmutex ldap mutexdn =
  let mt = new ldapentry in
  let mtrdn = List.hd (Ldap_dn.of_string mutexdn) in
    mt#set_dn mutexdn;



    mt#add [("objectclass", ["top";"mutex"]);
            (mtrdn.attr_type, mtrdn.attr_vals)];
    catch
      (fun () -> ldap#add mt)
      (fun exn -> fail (Ldap_mutex ("addmutex", exn)))

let rec lock (ldap:ldapcon) mutexdn lockval =
  catch begin fun () ->
    let obj =
      catch
        (fun () ->
           ldap#search
             ~base:mutexdn
             ~scope:`BASE
             "objectclass=*")
        (function LDAP_Failure (`NO_SUCH_OBJECT, _, _) -> return []
           | exn -> fail exn)
    in obj >>= fun obj ->
      if List.length obj = 0 then begin
        addmutex ldap mutexdn >>= fun () ->
        lock ldap mutexdn lockval
      end
      else if List.length obj = 1 then
        let rec loop () =
          catch
            (fun () ->
               ldap#modify (List.hd obj)#dn lockval >>= fun () ->
               fail (Failure "locked"))
            (function
               (* the mutex is locked already *)
                 LDAP_Failure (`TYPE_OR_VALUE_EXISTS, _, _)
               | LDAP_Failure (`OBJECT_CLASS_VIOLATION, _, _) ->
                   (* this is so evil *)
                   (* FIXME *)
                   ignore (Unix.select [] [] [] 0.25); (* wait 1/4 of a second *)
                   return ()
               | exn -> fail exn) >>= fun () ->
           loop ()
        in
          loop ()
      else fail (Failure "huge error, multiple objects with the same dn")
  end
  (function
    | Failure "locked" -> return ()
    | (Ldap_mutex _) as exn -> fail exn
    | exn -> fail (Ldap_mutex ("lock", exn)))

let rec unlock (ldap:ldapcon) mutexdn unlockval =
  catch begin fun () ->
    let obj =
      catch
        (fun () ->
           ldap#search
             ~base:mutexdn
             ~scope:`BASE
             "objectclass=*")
        (function LDAP_Failure (`NO_SUCH_OBJECT, _, _) -> return []
           | exn -> fail exn)
    in obj >>= fun obj ->
      if List.length obj = 0 then begin
        addmutex ldap mutexdn >>= fun () ->
        unlock ldap mutexdn unlockval
      end
      else if List.length obj = 1 then
        catch
          (fun () ->
             ldap#modify
               (List.hd obj)#dn unlockval)
          (function LDAP_Failure (`NO_SUCH_ATTRIBUTE, _, _) -> return ()
             | exn -> fail exn)
      else return ()
  end
  (function
      (Ldap_mutex _) as exn -> fail exn
    | exn -> fail (Ldap_mutex ("unlock", exn)))


class mutex ldapurls binddn bindpw mutexdn =
object (self)
  val ldap =
    let ldap = new ldapcon ldapurls in
      ldap#bind binddn ~cred:bindpw >>= fun () ->
      return ldap

  method private addmutex = ldap >>= fun ldap -> addmutex ldap mutexdn
  method lock = ldap >>= fun ldap -> lock ldap mutexdn [(`ADD, "mutexlocked", ["locked"])]
  method unlock = ldap >>= fun ldap -> unlock ldap mutexdn [(`DELETE, "mutexlocked", [])]
end

let apply_with_mutex mutex f =
  mutex#lock >>= fun () ->
  finalize f (fun () -> mutex#unlock)

class object_lock_table ldapurls binddn bindpw mutextbldn =
object (self)
  val ldap =
    let ldap = new ldapcon ldapurls in
      ldap#bind binddn ~cred:bindpw >>= fun () ->
      return ldap
  method private addmutex = ldap >>= fun ldap -> addmutex ldap mutextbldn
  method lock dn = ldap >>= fun ldap -> lock ldap mutextbldn [(`ADD, "lockedObject", [Ldap_dn.to_string dn])]
  method unlock dn = ldap >>= fun ldap -> unlock ldap mutextbldn [(`DELETE, "lockedObject", [Ldap_dn.to_string dn])]
end

end
