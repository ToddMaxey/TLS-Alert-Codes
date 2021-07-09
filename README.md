# TLS-Alert-Codes
Chart of TLS Alert codes culled from the internet


Alert Code	Alert Message				                Description
0		        close_notify				                Notifies the recipient that the sender will not send any more messages on this connection.
1		        no_cipher				                    Indicates that the requested cipher is not supported.
2		        no_certificate			            	  Sent by the client to indicate that he does not have a proper certificate to fulfill a certificate request from the server.
4		        bad_certificate				              Indicates that there is something wrong with the certificate received from the peer (e.g. the signature of the certificate is invalid).
6		        unsupported_certificate_type	      Indicates that the certificate type is not supported
10	      	unexpected_message			            Received an inappropriate message This alert should never be observed in communication between proper implementations. This message is always fatal.
20		      bad_record_mac				              Received a record with an incorrect MAC. This message is always fatal.
21		      decryption_failed			              "Decryption of a TLSCiphertext record is decrypted in an invalid way: either it was not an even multiple of the block length or its padding values, when checked, were not correct. This message is always fatal."
22	      	record_overflow			            	  "Received a TLSCiphertext record which had a length more than 2^14+2048 bytes, or a record decrypted to a TLSCompressed record with more than 2^14+1024 bytes. This message is always fatal."
30	      	decompression_failure		        	  "Received improper input, such as data that would expand to excessive length, from the decompression function. This message is always fatal."
40	      	handshake_failure			              Indicates that the sender was unable to negotiate an acceptable set of security parameters given the options available. This is a fatal error.
41	      	bad_certificate				              SSLv3 only
42		      no_certificate				              "There is a problem with the certificate, for example, a certificate is corrupt, or a certificate contains signatures that cannot be verified."
43	      	unsupported_certificate		      	  Received an unsupported certificate type.
44	      	certificate_revoked			            Received a certificate that was revoked by its signer.
45		      certificate_expired			            Received a certificate has expired or is not currently valid.
46		      certificate_unknown		              An unspecified issue took place while processing the certificate that made it unacceptable.
47	      	illegal_parameter		            	  "Violated security parameters, such as a field in the handshake was out of range or inconsistent with other fields. This is always fatal."
48	      	unknown_ca				                  "Received a valid certificate chain or partial chain, but the certificate was not accepted because the CA certificate could not be located or could not be matched with a known, trusted CA. This message is always fatal."
49	      	access_denied				                "Received a valid certificate, but when access control was applied, the sender did not proceed with negotiation. This message is always fatal."
50	      	decode_error				                A message could not be decoded because some field was out of the specified range or the length of the message was incorrect. This message is always fatal.
51	      	decrypt_error				                "Failed handshake cryptographic operation, including being unable to correctly verify a signature, decrypt a key exchange, or validate a finished message."
60		      export_restriction		              "Detected a negotiation that was not in compliance with export restrictions; for example, attempting to transfer a 1024 bit ephemeral RSA key for the RSA_EXPORT handshake method. This message is always fatal."
70	      	protocol_version			              "The protocol version the client attempted to negotiate is recognized, but not supported. For example, old protocol versions might be avoided for security reasons. This message is always fatal."
71		      insufficient_security			          Failed negotiation specifically because the server requires ciphers more secure than those supported by the client. Returned instead of handshake_failure. This message is always fatal.
80		      internal_error				              "An internal error unrelated to the peer or the correctness of the protocol makes it impossible to continue, such as a memory allocation failure. The error is not related to protocol. This message is always fatal."
86		      inappropriate_fallback			        "An internal error unrelated to the peer or the correctness of the protocol makes it impossible to continue, such as a memory allocation failure. The error is not related to protocol. This message is always fatal."
90	      	user_cancelled				              "Cancelled handshake for a reason that is unrelated to a protocol failure. If the user cancels an operation after the handshake is complete, just closing the connection by sending a close_notify is more appropriate. This alert should be followed by a close_notify. This message is generally a warning."
100		      no_renegotiation		                "Sent by the client in response to a hello request or sent by the server in response to a client hello after initial handshaking. Either of these would normally lead to renegotiation; when that is not appropriate, the recipient should respond with this alert; at that point, the original requester can decide whether to proceed with the connection. One case where this would be appropriate would be where a server has spawned a process to satisfy a request; the process might receive security parameters (key length, authentication, and so on) at start-up and it might be difficult to communicate changes to these parameters after that point. This message is always a warning."
109	      	missing_extension			              Indicates that an extension is missing from a handshake message for which this extension is mandatory.
110		      unsupported_extension			          Alert level: fatal. Sent by the client if the Server Hello does contain an extension that the client did not requested in his Client Hello.
111		      certificate_unobtainable_RESERVED	  Alert level: maybe fatal. Sent by the server to indicate that he cannot obtain a certificate from the URL the client has sent within a ClientCertificateURL extension.
112		      unrecognized_name			              Alert level: maybe fatal. Sent by the server if he does not recognize a server name included in the ServerNameList extension received from the client.
113		      bad_certificate_status_respons		  Alert level: fatal. Sent by the client if he gets an invalid certificate status response after having sent a CertificateStatusRequest extension.
114		      bad_certificate_hash_value_RESERVED	Alert level: fatal. Sent by the server if a certificate hash value does not match to the corresponding value received within a ClientCertificateURL extension message.
115		      unknown_psk_identity			          Indicates that the server does not recognize the PSK identity sent by the client.
116		      certificate_required			          RFC 8446 - Indicates that the server has requested a certificate but the client did not send one.
120		      no_application_protocol			        RFC 730 - No supported application protocol could be negotiated
255		      unsupported_extension			          Unsupported extension 
