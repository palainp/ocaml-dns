(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_mirage" ~doc:"effectful DNS layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (S : Tcpip.Stack.V4V6) = struct

  module IPM = struct
    include Map.Make(struct
        type t = Ipaddr.t * int
        let compare (ip, p) (ip', p') = match Ipaddr.compare ip ip' with
          | 0 -> compare p p'
          | x -> x
      end)
    let find k t = try Some (find k t) with Not_found -> None
  end

  module U = S.UDP
  module T = S.TCP

  type f = {
    flow : T.flow ;
    mutable linger : string ;
  }

  let of_flow flow = { flow ; linger = "" }

  let flow { flow ; _ } = flow

  let rec read_exactly f length =
    let dst_ip, dst_port = T.dst f.flow in
    let len = String.length f.linger in
    if len >= length then
      let a = String.sub f.linger 0 length in
      let b = String.sub f.linger length len in
      f.linger <- b ;
      Lwt.return (Ok a)
    else
      T.read f.flow >>= function
      | Ok `Eof ->
        Log.debug (fun m -> m "end of file on flow %a:%d" Ipaddr.pp dst_ip dst_port) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Error e ->
        Log.err (fun m -> m "error %a reading flow %a:%d" T.pp_error e Ipaddr.pp dst_ip dst_port) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Ok (`Data b) ->
        f.linger <- f.linger ^ (Cstruct.to_string b) ;
        read_exactly f length

  let send_udp stack src_port dst dst_port data =
    Log.debug (fun m -> m "udp: sending %d bytes from %d to %a:%d"
                 (String.length data) src_port Ipaddr.pp dst dst_port) ;
    U.write ~src_port ~dst ~dst_port (S.udp stack) (Cstruct.of_string data) >|= function
    | Error e -> Log.warn (fun m -> m "udp: failure %a while sending from %d to %a:%d"
                              U.pp_error e src_port Ipaddr.pp dst dst_port)
    | Ok () -> ()

  let send_tcp flow answer =
    let dst_ip, dst_port = T.dst flow in
    Log.debug (fun m -> m "tcp: sending %d bytes to %a:%d" (String.length answer) Ipaddr.pp dst_ip dst_port) ;
    let len = Bytes.create 2 in
    Bytes.set_uint16_be len 0 (String.length answer) ;
    let data = ((Bytes.unsafe_to_string len) ^ answer) in
    T.write flow (Cstruct.of_string data) >>= function
    | Ok () -> Lwt.return (Ok ())
    | Error e ->
      Log.err (fun m -> m "tcp: error %a while writing to %a:%d" T.pp_write_error e Ipaddr.pp dst_ip dst_port) ;
      T.close flow >|= fun () ->
      Error ()

  let send_tcp_multiple flow datas =
    Lwt_list.fold_left_s (fun acc d ->
        match acc with
        | Error () -> Lwt.return (Error ())
        | Ok () -> send_tcp flow d)
      (Ok ()) datas

  let read_tcp flow =
    read_exactly flow 2 >>= function
    | Error () -> Lwt.return (Error ())
    | Ok l ->
      let len = String.get_uint16_be l 0 in
      read_exactly flow len
end
