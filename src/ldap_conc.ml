open Ldap_types

let readbyte_of_readfun rfun =
  let bufsize = 16384 in (* must be this for ssl *)
  let buf = String.create (bufsize * 2) in
  let buf_len = ref 0 in
  let buf_pos = ref 0 in
  let peek_pos = ref 0 in
  let peek_buf_len = ref 0 in
  let read buf off len =
    try rfun buf off len
    with exn -> raise (Readbyte_error Transport_error)
  in
  let read_at_least_nbytes buf off len nbytes =
    let total = ref 0 in
      while !total < nbytes
      do
        let rd = read buf (!total + off) (len - !total) in
          if rd <= 0 then
            raise (Readbyte_error Transport_error);
          total := !total + rd;
      done;
      !total
  in
  let rec rb ?(peek=false) length =
    if length <= 0 then raise (Invalid_argument "Readbyte.length");
    if length > bufsize then (
      if length > Sys.max_string_length then raise (Readbyte_error Request_too_large);
      let result = String.create length in
      let total = ref 0 in
        while !total < length
        do
          let nbytes_to_read =
            if length - !total < bufsize then
              length - !total
            else bufsize
          in
          let iresult = rb ~peek nbytes_to_read in
            String.blit iresult 0 result !total nbytes_to_read;
            total := !total + nbytes_to_read
        done;
        result
    )
    else if not peek then (
      if length <= !buf_len - !buf_pos then (
        let result = String.sub buf !buf_pos length in
          buf_pos := !buf_pos + length;
          peek_pos := !buf_pos;
          result
      )
      else (
        let result = String.create length in
        let nbytes_really_in_buffer = (!buf_len - !buf_pos) + !peek_buf_len in
        let nbytes_in_buffer =
          if nbytes_really_in_buffer > length then length
          else nbytes_really_in_buffer
        in
        let nbytes_to_read = length - nbytes_in_buffer in
          if nbytes_in_buffer > 0 then
            String.blit buf !buf_pos result 0 nbytes_in_buffer;
          if nbytes_to_read > 0 then (
            let nbytes_read = read_at_least_nbytes buf 0 bufsize nbytes_to_read in
              String.blit buf 0 result nbytes_in_buffer nbytes_to_read;
              buf_pos := nbytes_to_read;
              buf_len := nbytes_read;
              peek_pos := !buf_pos;
              peek_buf_len := 0;
              result
          )
          else (
            String.blit buf 0 buf (!buf_pos + length) (nbytes_really_in_buffer - length);
            buf_len := (nbytes_really_in_buffer - length);
            buf_pos := 0;
            peek_pos := !buf_pos;
            peek_buf_len := 0;
            result
          )
      )
    ) (* if not peek *)
    else (
      if length <= (!buf_len + !peek_buf_len) - !peek_pos then (
        let result = String.sub buf !peek_pos length in
          peek_pos := !peek_pos + length;
          result
      )
      else (
        if length + !peek_pos > 2 * bufsize then raise (Readbyte_error Peek_error);
        let result = String.create length in
        let nbytes_in_buffer = (!buf_len + !peek_buf_len) - !peek_pos in
        let nbytes_to_read = length - nbytes_in_buffer in
        let read_start_pos = !peek_pos + nbytes_in_buffer in
          String.blit buf !peek_pos result 0 nbytes_in_buffer;
          let nbytes_read =
            read_at_least_nbytes buf
              read_start_pos
              (bufsize - (!buf_len + !peek_buf_len))
              nbytes_to_read
          in
            String.blit buf read_start_pos result nbytes_in_buffer nbytes_read;
            peek_buf_len := !peek_buf_len + nbytes_read;
            peek_pos := !peek_pos + length;
            result
      )
    )
  in
    rb

type ld_socket = Ssl of Ssl.socket
                 | Plain of Unix.file_descr

type fd = { fd : ld_socket; mutable closed : bool }

let close_fd fd =
  if not fd.closed then begin
    fd.closed <- true;
    match fd.fd with
      | Plain sock -> (try Unix.close sock with _ -> ())
      | Ssl ssl -> (try Ssl.shutdown ssl with _ -> ())
  end

(* a readbyte implementation which reads from an FD. It implements a
   peek buffer, so it can garentee that it will work with
   readbyte_of_ber_element, even with blocking fds. *)
let readbyte_of_unix_fd fd =
  readbyte_of_readfun
    (fun buf off len ->
       try Unix.read fd buf off len
       with exn ->
         (try Unix.close fd with _ -> ());
         raise exn)

let readbyte_of_fd t fd =
  readbyte_of_readfun
    (fun buf off len ->
       try Unix.read fd buf off len
       with exn ->
         (try close_fd t with _ -> ());
         raise exn)

(* a readbyte implementation which reads from an SSL socket. It is
   otherwise the same as rb_of_fd *)
let readbyte_of_ssl t fd =
  readbyte_of_readfun
    (fun buf off len ->
       try Ssl.read fd buf off len
       with exn ->
         (try close_fd t with _ -> ());
         raise exn)

module Id : Ldap_types.Monad with type 'a t = 'a =
struct
  type 'a t = 'a

  type readbyte = ?peek:bool -> int -> string

  let return x = x
  let bind x f = f x
  let fail = raise
  let catch f g = try f () with exn -> g exn
  let finalize f g =
    try let x = f () in g (); x
    with exn -> g (); raise exn

  module IO =
  struct

    let _ = Ssl.init ()

    type input_channel = fd
    type output_channel = fd

    let connect meth ~connect_timeout addr port =
      let previous_signal = ref Sys.Signal_default in
        try
          if meth = `PLAIN then
            let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
              try
                previous_signal :=
                Sys.signal Sys.sigalrm
                  (Sys.Signal_handle (fun _ -> failwith "timeout"));
                ignore (Unix.alarm connect_timeout);
                Unix.connect s (Unix.ADDR_INET (addr, port));
                ignore (Unix.alarm 0);
                Sys.set_signal Sys.sigalrm !previous_signal;
                Some (Plain s)
              with exn -> Unix.close s;raise exn
              else
                (previous_signal :=
                 Sys.signal Sys.sigalrm
                   (Sys.Signal_handle (fun _ -> failwith "timeout"));
                 ignore (Unix.alarm connect_timeout);
                 let ssl = Ssl (Ssl.open_connection
                                  Ssl.SSLv23
                                  (Unix.ADDR_INET (addr, port)))
                 in
                   ignore (Unix.alarm 0);
                   Sys.set_signal Sys.sigalrm !previous_signal;
                   Some (ssl))
       with
           Unix.Unix_error (Unix.ECONNREFUSED, _, _)
         | Unix.Unix_error (Unix.EHOSTDOWN, _, _)
         | Unix.Unix_error (Unix.EHOSTUNREACH, _, _)
         | Unix.Unix_error (Unix.ECONNRESET, _, _)
         | Unix.Unix_error (Unix.ECONNABORTED, _, _)
         | Ssl.Connection_error _
         | Failure "timeout" ->
             ignore (Unix.alarm 0);
             Sys.set_signal Sys.sigalrm !previous_signal;
             None

    let connect meth ~connect_timeout addr port =
      match connect meth ~connect_timeout addr port with
        | None -> None
        | Some fd -> let fd = { fd; closed = false } in Some (fd, fd)

    let close_out = close_fd
    let close_in = close_fd

    let readbyte_of_input_channel ic = match ic.fd with
      | Plain fd -> readbyte_of_fd ic fd
      | Ssl ssl -> readbyte_of_ssl ic ssl

    let write ld_socket buf off len =
      match ld_socket with
          Ssl s ->
            (try Ssl.write s buf off len
             with Ssl.Write_error _ -> raise (Unix.Unix_error (Unix.EPIPE, "Ssl.write", "")))
        | Plain s -> Unix.write s buf off len

    let write oc s =
      let len     = String.length s in
      let written = ref 0 in
        while !written < len do
          written := !written + write oc.fd s !written (len - !written)
        done
  end
end
