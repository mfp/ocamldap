
module Id : Ldap_types.Monad with type 'a t = 'a =
struct
  type 'a t = 'a

  let return x = x
  let bind x f = f x
  let fail = raise
  let catch f g = try f () with exn -> g exn
  let finalize f g =
    try let x = f () in g (); x
    with exn -> g (); raise exn
end
