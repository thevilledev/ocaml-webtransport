(** QUIC v1 frames (RFC 9000 s.19), DATAGRAM (RFC 9221) and RESET_STREAM_AT
    (draft-ietf-quic-reliable-stream-reset). Parsing is total; payloads are
    zero-copy views into the parse buffer. *)

type payload = { buf : Bigstringaf.t; off : int; len : int }

val payload_of_string : string -> payload
val payload_to_string : payload -> string
val empty_payload : payload

type t =
  | Padding of int  (** run length *)
  | Ping
  | Ack of {
      largest : int;
      delay : int;  (** raw, pre-exponent *)
      ranges : (int * int) list;  (** (lo, hi) inclusive, descending *)
      ecn : (int * int * int) option;
    }
  | Reset_stream of { id : int; code : int; final_size : int }
  | Stop_sending of { id : int; code : int }
  | Crypto of { off : int; data : payload }
  | New_token of { token : payload }
  | Stream of { id : int; off : int; fin : bool; data : payload }
  | Max_data of int
  | Max_stream_data of { id : int; max : int }
  | Max_streams_bidi of int
  | Max_streams_uni of int
  | Data_blocked of int
  | Stream_data_blocked of { id : int; max : int }
  | Streams_blocked_bidi of int
  | Streams_blocked_uni of int
  | New_connection_id of {
      seq : int;
      retire_prior_to : int;
      cid : string;
      reset_token : string;
    }
  | Retire_connection_id of int
  | Path_challenge of string
  | Path_response of string
  | Connection_close of {
      app : bool;
      code : int;
      frame_type : int;
      reason : payload;
    }
  | Handshake_done
  | Datagram of { data : payload }
  | Reset_stream_at of {
      id : int;
      code : int;
      final_size : int;
      reliable_size : int;
    }

val is_ack_eliciting : t -> bool
val parse_one : Wire.reader -> (t, string) result
val parse_all : Bigstringaf.t -> off:int -> len:int -> (t list, string) result

val size : t -> int
val encode : Bigstringaf.t -> off:int -> t -> int
(** returns bytes written; [size] agrees with it. *)
