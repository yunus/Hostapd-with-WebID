/*
 * Created by Yunus Durmus
 * yunus@yanis.co
 * This file enables webid support for EAP-TLS.
 * If trust functionality is required, you also need to 
 * install git://github.com/yunus/python-webid.git

 * */

#include "includes.h"
#include "redland.h"
#include "webid.h"
#include "common.h"

#ifdef EAP_SERVER_STLS_AUTHORIZATION
	#include <Python.h>
	static const char *serv_webid;
	static char *webid_method;
#endif




static int
hex_or_x(int c) {
    if (c >= '0' && c <= '9')
        return c;
    c |= 32;
    if (c >= 'a' && c <= 'f')
        return c;
    return 'x';
}

static int
matches_pkey(unsigned char *s, char *pkey) {
    if (s == NULL || pkey == NULL)
        return 0;
    // eliminate leading zeros
    while (s[0] == '0') s++;
    while (pkey[0] == '0') pkey++;
    unsigned int s_s = strlen((const char*)s);
    unsigned int s_pkey = strlen(pkey);
    unsigned int fc, pc, j, k = 0;

    for (j = 0; j < s_s; j++) {
        if ((fc = hex_or_x(s[j])) == 'x')
            continue;
        pc = hex_or_x(pkey[k]);
        if (fc != pc)
            break;
        k++;
    }
    if (k == s_pkey)
        return 1;
    return 0;
}

#ifdef EAP_SERVER_STLS_AUTHORIZATION
int
trust( const char* san_uri)
{
    PyObject  *pModule;
    PyObject *pValue;
    int  is_trusted = 0;

    Py_Initialize();
    pModule = PyImport_ImportModule(WEBID_MODULE);

    if (pModule != NULL) {

        	pValue = PyObject_CallMethod(pModule,webid_method,"ss", serv_webid, san_uri);
        	/* pValue is a new reference*/

            if (pValue != NULL &&  PyBool_Check(pValue)) {
            	is_trusted = PyObject_IsTrue(pValue);
            	wpa_printf(MSG_DEBUG,"STLS: Result from %s is %d",webid_method,is_trusted);            
                Py_DECREF(pValue);
            }
            else {                
                Py_DECREF(pModule);
                PyErr_Print();
                wpa_printf(MSG_ERROR,"STLS: A problem occured in trust method call");                
                return 0;
            }
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        wpa_printf(MSG_ERROR,"STLS: Failed to load %s, check installation of external library.",
        		WEBID_MODULE);         
        return 0;
    }
    Py_Finalize();
    return is_trusted;
}

void set_server_webid(const char* webid, const char* webid_m){
	serv_webid = webid;
	if(os_strcmp(webid_m,"direct") == 0)
		webid_method = WEBID_DIRECT_METHOD;
	else
		webid_method = WEBID_TRANSITIVE_METHOD;
	
}

#endif /*EAP_SERVER_STLS_AUTHORIZATION*/

int
validate_webid(const char *subjAltName, char *pkey_n, unsigned int pkey_e_i) {
    int r = 0;

    librdf_world *rdf_world = NULL;
    librdf_storage *rdf_storage = NULL;
    librdf_model *rdf_model = NULL;
    librdf_query *rdf_query = NULL;
    librdf_query_results *rdf_query_results = NULL;

    rdf_world = librdf_new_world();
    if (rdf_world != NULL) {
        librdf_world_open(rdf_world);
        rdf_storage = librdf_new_storage(rdf_world, "uri", subjAltName, NULL);
        if (rdf_storage != NULL) {
            rdf_model = librdf_new_model(rdf_world, rdf_storage, NULL);
        } else
            wpa_printf(MSG_WARNING,"STLS: librdf_new_storage returned NULL");

    }

    if (rdf_model != NULL) {
       
        rdf_query = librdf_new_query(rdf_world, "sparql", NULL, (const unsigned char*) SPARQL_WEBID /*c_query*/, NULL);

    } else {
		wpa_printf(MSG_WARNING, "STLS: librdf_new_model returned NULL");
    }

    if (rdf_query != NULL) {
		wpa_printf(MSG_DEBUG,"STLS: just before executing the query");
        rdf_query_results = librdf_query_execute(rdf_query, rdf_model);
        if (rdf_query_results != NULL) {
			
            for (; r != 1 && librdf_query_results_finished(rdf_query_results)==0; librdf_query_results_next(rdf_query_results)) {
                librdf_node *m_node, *e_node;
                unsigned char *rdf_mod;
                unsigned char *rdf_exp;

                        m_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "mod");

                        e_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "exp");


                    if (librdf_node_is_literal(m_node) && librdf_node_is_literal(e_node)) {
                        rdf_mod = librdf_node_get_literal_value(m_node);
                        rdf_exp = librdf_node_get_literal_value(e_node);

                        wpa_printf(MSG_DEBUG,"STLS: modulus = %s, exponent: %s", rdf_mod, rdf_exp);
                        

                        if (rdf_exp != NULL
                            && strtol((char*)rdf_exp, NULL, 10) == (long)pkey_e_i 
                            && matches_pkey(rdf_mod, pkey_n))
                            r = 1;
                        librdf_free_node(m_node);
                        librdf_free_node(e_node);
                    }

            }
            librdf_free_query_results(rdf_query_results);
        } else
            wpa_printf(MSG_WARNING, "STLS: librdf_query_execute returned NULL");
        librdf_free_query(rdf_query);
    } else
        wpa_printf(MSG_WARNING, "STLS: librdf_new_query returned NULL");

    if (rdf_model) librdf_free_model(rdf_model);
    if (rdf_storage) librdf_free_storage(rdf_storage);
    if (rdf_world) librdf_free_world(rdf_world);

    return r;
}


