def is_two_args_calldata_ptr(type_str):
    if type_str.startswith("t_function_external"):
        return True
    elif type_str in ("t_bytes_calldata_ptr", "t_string_calldata_ptr"):
        return True
    elif type_str.startswith("t_array") and type_str.endswith("dyn_calldata_ptr"):
        return True
    else:
        return False
