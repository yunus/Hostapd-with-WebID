
#define SPARQL_WEBID \
	"PREFIX cert: <http://www.w3.org/ns/auth/cert#> "\
"PREFIX rsa: <http://www.w3.org/ns/auth/rsa#> "\
"SELECT ?mod ?exp "\
"WHERE { [] cert:key [ "\
"cert:modulus ?mod; "\
"cert:exponent ?exp; "\
"] . " \
"}" \
	
	/*
    "PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>" \
    "PREFIX cert: <http://www.w3.org/ns/auth/cert#>" \
    "SELECT ?m ?e ?mod ?exp WHERE {" \
    "  ?key cert:identity <%s>; rsa:modulus ?m; rsa:public_exponent ?e." \
    "  OPTIONAL { ?m cert:hex ?mod. }" \
    "  OPTIONAL { ?e cert:decimal ?exp. }" \
    "}"*/


#define WEBID_MODULE "webid.authorizer"
#define WEBID_DIRECT_METHOD "__direct_trust"
#define WEBID_TRANSITIVE_METHOD "__transitive_trust"

#ifdef EAP_SERVER_STLS_AUTHORIZATION
/*
 * trust - webid authorization checker
 * 
 * @san_uri: The uri of the connecting peer. In the certificate under Subject Alternative Name (SAN) field
 * @method: defines whether direct trust or transitive trust will be used. USE the above WEBID_*_METHOD definitions
 * return: integer 0 => not authorized, 1=> authorized
 * 
 * 
 * Checks whether the peers trust (authorize) each other.
 * Also this method requires  git://github.com/yunus/python-webid.git to be installed Since it calls python library.
*/
int trust( const char* san_uri, char* method);

/*
 * set_server_webid - sets the server device's webid url
 * @webid: the server's webid
 * 
 * the server_webid entered in the config file is set as a global variable
 * 
 * */
void set_server_webid(const char* webid);

#endif /*EAP_SERVER_STLS_AUTHORIZATION*/



/*
 * validate_webid - Webid authentication protocol
 * @subjAltName: The uri address under Subject Alt Name field of the certificate
 * @pkey_n: public key in hex
 * @pkey_e_i: exponent
 * return: integer 0 => not authenticated, 1=> authenticated
 * 
 * Deals with webid authentication. Written in pure C only requires librdf for rdf parsing.
 * If authorization is not required the trust method above can be skipped.
 * */
int validate_webid(const char *subjAltName, char *pkey_n, unsigned int pkey_e_i); 