/*
 * EAP-SocTLS authentication protocol python bridge and common variables/functions
 * Yunus Durmus (yunus@yanis.co)
 *
 */


#ifndef _WEBID_H_
#define _WEBID_H_


#include "utils/common.h"

#define SPARQL_WEBID \
	"PREFIX cert: <http://www.w3.org/ns/auth/cert#> "\
"PREFIX rsa: <http://www.w3.org/ns/auth/rsa#> "\
"SELECT ?mod ?exp "\
"WHERE { [] cert:key [ "\
"cert:modulus ?mod; "\
"cert:exponent ?exp; "\
"] . " \
"}" \
	


#define WEBID_AUTHORIZER_MODULE "webid.authorizer"
#define WEBID_SNIFFER_MODULE "webid.sniffer"
#define WEBID_DIRECT_METHOD "__direct_trust"
#define WEBID_TRANSITIVE_METHOD "__transitive_trust"
#define WEBID_ALL_METHOD "__trust"
#define WEBID_SNIFF_METHOD "add_mac_address"

#ifdef EAP_SERVER_STLS_AUTHORIZATION
/*
 * trust - webid authorization checker
 * 
 * @san_uri: The uri of the connecting peer. In the certificate under Subject Alternative Name (SAN) field
 *
 * return: integer 0 => not authorized, 1=> authorized
 * 
 * 
 * Checks whether the peers trust (authorize) each other.
 * Also this method requires  git://github.com/yunus/python-webid.git to be installed Since it calls python library.
*/
int trust( const char* san_uri);

/*
 * init_webid - sets the server device's webid url
 * @webid: the server's webid
 * @webid_m: defines whether direct trust or transitive trust will be used, options are:
 * direct,transitive,all
 * 
 * the server_webid entered in the config file is set as a global variable
 * the webid_auth_method entered in the config file is set as a global variable
 * the data structure for mac addresses is initialized.
 * Python interpreter is started.
 * 
 * */
void init_webid(const char* webid, const char* webid_m);


/*
 *
 * We need to supply mac address information to the webid validator in order to
 * use context information. However, tls_openssl does not have any information about
 * the mac address, it only checks the certificate. Therefore, we create some global variables
 * and to store mac addresses that are being authenticated.
 * We tried to map certificates to mac addresses but certificate information is only available in openssl level.
 * */
void webid_add_new_station(const u8 *addr);
void webid_remove_station(const u8 *addr);

/*
 * add_mac - calls python module to persist the sniffed mac address
 * @addr - mac address array
 * sniffed probe requests are persisted to the database.
 * Later on sniffed mac addresses will be used to infer context.
 * */
void add_mac(const u8 *addr);

/*
 * We need to finalize embedded python
 * */
void deinit_webid();

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



#endif // #ifndef _WEBID_H_
