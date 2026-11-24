require "openssl/lib_crypto"

lib LibCrypto
  type EvpPkey = Void
  type EvpPkeyCtx = Void

  EVP_PKEY_X25519  = 1034
  EVP_PKEY_ED25519 = 1087

  fun evp_pkey_ctx_new_id = EVP_PKEY_CTX_new_id(id : LibC::Int, engine : Void*) : EvpPkeyCtx*
  fun evp_pkey_ctx_new = EVP_PKEY_CTX_new(pkey : EvpPkey*, engine : Void*) : EvpPkeyCtx*
  fun evp_pkey_ctx_free = EVP_PKEY_CTX_free(ctx : EvpPkeyCtx*)
  fun evp_pkey_keygen_init = EVP_PKEY_keygen_init(ctx : EvpPkeyCtx*) : LibC::Int
  fun evp_pkey_keygen = EVP_PKEY_keygen(ctx : EvpPkeyCtx*, pkey : EvpPkey**) : LibC::Int
  fun evp_pkey_free = EVP_PKEY_free(pkey : EvpPkey*)

  fun evp_pkey_new_raw_public_key = EVP_PKEY_new_raw_public_key(type : LibC::Int, engine : Void*, key : UInt8*, keylen : LibC::SizeT) : EvpPkey*
  fun evp_pkey_new_raw_private_key = EVP_PKEY_new_raw_private_key(type : LibC::Int, engine : Void*, key : UInt8*, keylen : LibC::SizeT) : EvpPkey*
  fun evp_pkey_get_raw_public_key = EVP_PKEY_get_raw_public_key(pkey : EvpPkey*, pub : UInt8*, len : LibC::SizeT*) : LibC::Int
  fun evp_pkey_get_raw_private_key = EVP_PKEY_get_raw_private_key(pkey : EvpPkey*, priv : UInt8*, len : LibC::SizeT*) : LibC::Int

  fun evp_pkey_derive_init = EVP_PKEY_derive_init(ctx : EvpPkeyCtx*) : LibC::Int
  fun evp_pkey_derive_set_peer = EVP_PKEY_derive_set_peer(ctx : EvpPkeyCtx*, peer : EvpPkey*) : LibC::Int
  fun evp_pkey_derive = EVP_PKEY_derive(ctx : EvpPkeyCtx*, key : UInt8*, keylen : LibC::SizeT*) : LibC::Int

  fun evp_digest_sign_init = EVP_DigestSignInit(ctx : EVP_MD_CTX, pctx : Void*, type : Void*, engine : Void*, pkey : EvpPkey*) : LibC::Int
  fun evp_digest_sign = EVP_DigestSign(ctx : EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
  fun evp_digest_verify_init = EVP_DigestVerifyInit(ctx : EVP_MD_CTX, pctx : Void*, type : Void*, engine : Void*, pkey : EvpPkey*) : LibC::Int
  fun evp_digest_verify = EVP_DigestVerify(ctx : EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
end

module Crypto
  module X25519
    KEY_SIZE    = 32
    SECRET_SIZE = 32

    class KeyPair
      getter public_key : Bytes

      def initialize
        ctx = LibCrypto.evp_pkey_ctx_new_id(LibCrypto::EVP_PKEY_X25519, nil)
        raise "X25519: failed to create context" if ctx.null?
        begin
          raise "X25519: keygen_init failed" unless LibCrypto.evp_pkey_keygen_init(ctx) == 1
          pkey = Pointer(LibCrypto::EvpPkey).null
          raise "X25519: keygen failed" unless LibCrypto.evp_pkey_keygen(ctx, pointerof(pkey)) == 1
          @pkey = pkey
        ensure
          LibCrypto.evp_pkey_ctx_free(ctx)
        end
        @public_key = extract_public_key
      end

      def initialize(private_key : Bytes)
        raise "X25519: private key must be #{KEY_SIZE} bytes" unless private_key.size == KEY_SIZE
        @pkey = LibCrypto.evp_pkey_new_raw_private_key(
          LibCrypto::EVP_PKEY_X25519, nil, private_key, KEY_SIZE)
        raise "X25519: failed to load private key" if @pkey.null?
        @public_key = extract_public_key
      end

      def derive(peer_public_key : Bytes) : Bytes
        raise "X25519: peer key must be #{KEY_SIZE} bytes" unless peer_public_key.size == KEY_SIZE
        peer = LibCrypto.evp_pkey_new_raw_public_key(
          LibCrypto::EVP_PKEY_X25519, nil, peer_public_key, KEY_SIZE)
        raise "X25519: failed to load peer key" if peer.null?

        begin
          ctx = LibCrypto.evp_pkey_ctx_new(@pkey, nil)
          raise "X25519: derive context failed" if ctx.null?
          begin
            raise "X25519: derive_init failed" unless LibCrypto.evp_pkey_derive_init(ctx) == 1
            raise "X25519: set_peer failed" unless LibCrypto.evp_pkey_derive_set_peer(ctx, peer) == 1
            len = LibC::SizeT.new(SECRET_SIZE)
            secret = Bytes.new(SECRET_SIZE)
            raise "X25519: derive failed" unless LibCrypto.evp_pkey_derive(ctx, secret, pointerof(len)) == 1
            secret
          ensure
            LibCrypto.evp_pkey_ctx_free(ctx)
          end
        ensure
          LibCrypto.evp_pkey_free(peer)
        end
      end

      def finalize
        LibCrypto.evp_pkey_free(@pkey) unless @pkey.null?
      end

      private def extract_public_key : Bytes
        len = LibC::SizeT.new(KEY_SIZE)
        pub = Bytes.new(KEY_SIZE)
        raise "X25519: get_raw_public_key failed" unless LibCrypto.evp_pkey_get_raw_public_key(@pkey, pub, pointerof(len)) == 1
        pub
      end
    end
  end

  module Ed25519
    KEY_SIZE = 32
    SIG_SIZE = 64

    class KeyPair
      getter public_key : Bytes

      def initialize
        ctx = LibCrypto.evp_pkey_ctx_new_id(LibCrypto::EVP_PKEY_ED25519, nil)
        raise "Ed25519: failed to create context" if ctx.null?
        begin
          raise "Ed25519: keygen_init failed" unless LibCrypto.evp_pkey_keygen_init(ctx) == 1
          pkey = Pointer(LibCrypto::EvpPkey).null
          raise "Ed25519: keygen failed" unless LibCrypto.evp_pkey_keygen(ctx, pointerof(pkey)) == 1
          @pkey = pkey
        ensure
          LibCrypto.evp_pkey_ctx_free(ctx)
        end
        @public_key = extract_public_key
      end

      def initialize(private_key : Bytes)
        raise "Ed25519: private key must be #{KEY_SIZE} bytes" unless private_key.size == KEY_SIZE
        @pkey = LibCrypto.evp_pkey_new_raw_private_key(
          LibCrypto::EVP_PKEY_ED25519, nil, private_key, KEY_SIZE)
        raise "Ed25519: failed to load private key" if @pkey.null?
        @public_key = extract_public_key
      end

      def sign(message : Bytes) : Bytes
        ctx = LibCrypto.evp_md_ctx_new
        raise "Ed25519: failed to create MD context" if ctx.null?
        begin
          raise "Ed25519: sign_init failed" unless LibCrypto.evp_digest_sign_init(ctx, nil, nil, nil, @pkey) == 1
          siglen = LibC::SizeT.new(SIG_SIZE)
          sig = Bytes.new(SIG_SIZE)
          raise "Ed25519: sign failed" unless LibCrypto.evp_digest_sign(ctx, sig, pointerof(siglen), message, message.size) == 1
          sig
        ensure
          LibCrypto.evp_md_ctx_free(ctx)
        end
      end

      def raw_private_key : Bytes
        len = LibC::SizeT.new(KEY_SIZE)
        priv = Bytes.new(KEY_SIZE)
        raise "Ed25519: get_raw_private_key failed" unless LibCrypto.evp_pkey_get_raw_private_key(@pkey, priv, pointerof(len)) == 1
        priv
      end

      def finalize
        LibCrypto.evp_pkey_free(@pkey) unless @pkey.null?
      end

      private def extract_public_key : Bytes
        len = LibC::SizeT.new(KEY_SIZE)
        pub = Bytes.new(KEY_SIZE)
        raise "Ed25519: get_raw_public_key failed" unless LibCrypto.evp_pkey_get_raw_public_key(@pkey, pub, pointerof(len)) == 1
        pub
      end
    end

    def self.verify(public_key : Bytes, message : Bytes, signature : Bytes) : Bool
      raise "Ed25519: public key must be #{KEY_SIZE} bytes" unless public_key.size == KEY_SIZE
      raise "Ed25519: signature must be #{SIG_SIZE} bytes" unless signature.size == SIG_SIZE

      pkey = LibCrypto.evp_pkey_new_raw_public_key(
        LibCrypto::EVP_PKEY_ED25519, nil, public_key, KEY_SIZE)
      return false if pkey.null?

      begin
        ctx = LibCrypto.evp_md_ctx_new
        return false if ctx.null?
        begin
          return false unless LibCrypto.evp_digest_verify_init(ctx, nil, nil, nil, pkey) == 1
          LibCrypto.evp_digest_verify(ctx, signature, SIG_SIZE, message, message.size) == 1
        ensure
          LibCrypto.evp_md_ctx_free(ctx)
        end
      ensure
        LibCrypto.evp_pkey_free(pkey)
      end
    end
  end
end
