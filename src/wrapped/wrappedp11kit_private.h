#if !(defined(GO) && defined(GOM) && defined(GO2) && defined(DATA))
error Meh...
#endif

//GO(C_GetFunctionList, LFp)
//GO(C_GetInterface, LFpppL)
//GO(C_GetInterfaceList, LFpp)
GO(p11_kit_be_loud, vFv)
GO(p11_kit_be_quiet, vFv)
GO(p11_kit_config_option, pFp)
GO(p11_kit_finalize_module, vFp)
GO(p11_kit_finalize_registered, vFv)
GO(p11_kit_initialize_module, LFp)
GO(p11_kit_initialize_registered, vFv)
//GO(p11_kit_iter_add_callback, 
//GO(p11_kit_iter_add_filter, 
//GO(p11_kit_iter_begin_with, 
//GO(p11_kit_iter_begin, 
GO(p11_kit_iter_destroy_object, LFp)
GO(p11_kit_iter_free, vFp)
//GO(p11_kit_iter_get_attributes, 
//GO(p11_kit_iter_get_kind, 
GO(p11_kit_iter_get_module, pFp)
//GO(p11_kit_iter_get_object, 
//GO(p11_kit_iter_get_session, 
//GO(p11_kit_iter_get_slot_info, 
//GO(p11_kit_iter_get_slot, 
//GO(p11_kit_iter_get_token, 
GO(p11_kit_iter_keep_session, vFp)
GO(p11_kit_iter_load_attributes, LFppL)
//GO(p11_kit_iter_new, 
GO(p11_kit_iter_next, LFp)
GO(p11_kit_iter_set_uri, vFpp)
GO(p11_kit_load_initialize_module, pFp)
GO(p11_kit_message, pFv)
GO(p11_kit_module_finalize, LFp)
GO(p11_kit_module_for_name, pFp)
GO(p11_kit_module_get_filename, pFp)
GO(p11_kit_module_get_flags, LFp)
GO(p11_kit_module_get_name, pFp)
GO(p11_kit_module_initialize, LFp)
GO(p11_kit_module_load, pFpp)
GO(p11_kit_module_release, vFp)
//GO(p11_kit_modules_finalize_and_release, 
//GO(p11_kit_modules_finalize, 
//GO(p11_kit_modules_initialize, 
GO(p11_kit_modules_load_and_initialize, pFi)
//GO(p11_kit_modules_load, 
//GO(p11_kit_modules_release, 
//GO(p11_kit_override_system_files, 
GO(p11_kit_pin_file_callback, pFpppup)
GO(p11_kit_pin_get_length, LFp)
GO(p11_kit_pin_get_value, pFpp)
//GO(p11_kit_pin_new_for_buffer, 
GO(p11_kit_pin_new_for_string, pFp)
//GO(p11_kit_pin_new, 
//GO(p11_kit_pin_ref, 
GOM(p11_kit_pin_register_callback, iFEpppp)
GO(p11_kit_pin_request, vFpppu)
GO(p11_kit_pin_unref, vFp)
GOM(p11_kit_pin_unregister_callback, vFEppp)
//GO(p11_kit_registered_module_to_name, 
//GO(p11_kit_registered_modules, 
//GO(p11_kit_registered_name_to_module, 
//GO(p11_kit_registered_option, 
//GO(p11_kit_remote_serve_module, 
//GO(p11_kit_remote_serve_token, 
//GO(p11_kit_remote_serve_tokens, 
//GO(p11_kit_set_progname, 
GO(p11_kit_space_strdup, pFpL)
GO(p11_kit_space_strlen, LFpL)
GO(p11_kit_strerror, pFL)
GO(p11_kit_uri_any_unrecognized, iFp)
GO(p11_kit_uri_clear_attribute, iFpL)
//GO(p11_kit_uri_clear_attributes, 
GO(p11_kit_uri_format, iFpup)
GO(p11_kit_uri_free, vFp)
GO(p11_kit_uri_get_attribute, pFpL)
GO(p11_kit_uri_get_attributes, pFpp)
GO(p11_kit_uri_get_module_info, pFp)
//GO(p11_kit_uri_get_module_name, 
GO(p11_kit_uri_get_module_path, pFp)
GO(p11_kit_uri_get_pin_source, pFp)
GO(p11_kit_uri_get_pin_value, pFp)
//GO(p11_kit_uri_get_pinfile, 
GO(p11_kit_uri_get_slot_id, LFp)
GO(p11_kit_uri_get_slot_info, pFp)
GO(p11_kit_uri_get_token_info, pFp)
GO(p11_kit_uri_get_vendor_query, pFpp)
GO(p11_kit_uri_match_attributes, iFppL)
GO(p11_kit_uri_match_module_info, iFpp)
GO(p11_kit_uri_match_slot_info, iFpp)
GO(p11_kit_uri_match_token_info, iFpp)
GO(p11_kit_uri_message, pFi)
GO(p11_kit_uri_new, pFv)
GO(p11_kit_uri_parse, iFpup)
GO(p11_kit_uri_set_attribute, iFpp)
GO(p11_kit_uri_set_attributes, iFppL)
//GO(p11_kit_uri_set_module_name, 
GO(p11_kit_uri_set_module_path, vFpp)
//GO(p11_kit_uri_set_pin_source, 
//GO(p11_kit_uri_set_pin_value, 
//GO(p11_kit_uri_set_pinfile, 
GO(p11_kit_uri_set_slot_id, vFpL)
GO(p11_kit_uri_set_unrecognized, vFpi)
GO(p11_kit_uri_set_vendor_query, iFppp)
