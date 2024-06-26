#pragma once

using i8 = uint8_t;
using i16 = short;
using i32 = int;

#pragma pack(push, 1)
template <typename T>
struct be {
    T value;

    be() = default;
    template <typename U> be(const U &v) {
        value = v;
        swap();
    }
    operator auto() const {
        return std::byteswap(value);
    }
    template <typename U> be &operator+=(const U &v) {
        swap() += v;
        swap();
        return *this;
    }
    be &operator--() {
        --swap();
        swap();
        return *this;
    }
    T &swap() {
        return value = std::byteswap(value);
    }
};
using be_i32 = be<i32>;

struct header {
    i8 type;
    be_i32 length;
};

struct message {
    header h;
    std::vector<i8> data;

    template <typename T>
    T &get() {
        return *(T*)(data.data());
    }
};

//

struct authentication_ok {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 0;

    i8 type{'R'};
    be_i32 length{8};
    be_i32 auth_type_{0};
};

struct authentication_kerberos_v5 {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 2;

    i8 type{'R'};
    be_i32 length{8};
    be_i32 auth_type_{2};
};

struct authentication_cleartext_password {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 3;

    i8 type{'R'};
    be_i32 length{8};
    be_i32 auth_type_{3};
};

struct authentication_md5_password {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 5;

    i8 type{'R'};
    be_i32 length{12};
    be_i32 auth_type_{5};
    i8 the_salt_to_use_when_encrypting_the_password[4];
};

struct authentication_gss {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 7;

    i8 type{'R'};
    be_i32 length{8};
    be_i32 auth_type_{7};
};

struct authentication_gss_continue {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 8;

    i8 type{'R'};
    be_i32 length;
    be_i32 auth_type_{8};
    i8 *gssapi_or_sspi_authentication_data;
};

struct authentication_sspi {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 9;

    i8 type{'R'};
    be_i32 length{8};
    be_i32 auth_type_{9};
};

struct authentication_sasl {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 10;

    i8 type{'R'};
    be_i32 length;
    be_i32 auth_type_{10};

    auto authentication_mechanism() const {
        auto base = (const char *)&auth_type_ + sizeof(auth_type_);
        std::vector<std::string_view> v;
        while (*base) {
            v.emplace_back(base);
            base += v.back().size() + 1;
        }
        return v;
    }
};

struct authentication_sasl_continue {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 11;

    i8 type{'R'};
    be_i32 length;
    be_i32 auth_type_{11};
    //i8 *sasl_data_specific_to_the_sasl_mechanism_being_used;

    auto server_data() const {
        auto base = (const char *)&auth_type_ + sizeof(auth_type_);
        std::string_view v{base, base + length - sizeof(length) - sizeof(auth_type_)};
        return v;
    }
};

struct authentication_sasl_final {
    static constexpr inline bool backend_type = true;
    static constexpr inline i32 auth_type = 12;

    i8 type{'R'};
    be_i32 length;
    be_i32 auth_type_{12};
    //i8 *sasl_outcome_additional_data__specific_to_the_sasl_mechanism_being_used;

    auto server_data() const {
        auto base = (const char *)&auth_type_ + sizeof(auth_type_);
        std::string_view v{base, base + length - sizeof(length) - sizeof(auth_type_)};
        return v;
    }
};

struct backend_key_data {
    static constexpr inline bool backend_type = true;

    i8 type{'K'};
    be_i32 length{12};
    be_i32 the_process_id_of_this_backend;
    be_i32 the_secret_key_of_this_backend;
};

struct bind {
    static constexpr inline bool frontend_type = true;

    i8 type{'B'};
    be_i32 length;
    //std::string the_name_of_the_destination_portal_an_empty_string_selects_the_unnamed_portal_;
    //std::string the_name_of_the_source_prepared_statement_an_empty_string_selects_the_unnamed_prepared_statement_;
    //i16 the_number_of_parameter_format_codes_that_follow_denoted_c_below_;
    //i16 the_parameter_format_codes;
    //i16 the_number_of_parameter_values_that_follow_possibly_zero_;
    //i32 the_length_of_the_parameter_value_in_bytes_this_count_does_not_include_itself_;
    //i8 *the_value_of_the_parameter_in_the_format_indicated_by_the_associated_format_code;
    //i16 the_number_of_result_column_format_codes_that_follow_denoted_r_below_;
    //i16 the_result_column_format_codes;
};

struct bind_complete {
    static constexpr inline bool backend_type = true;

    i8 type{'2'};
    be_i32 length{4};
};

struct cancel_request {
    static constexpr inline bool frontend_type = true;

    be_i32 length{16};
    i32 the_cancel_request_code{80877102};
    i32 the_process_id_of_the_target_backend;
    i32 the_secret_key_for_the_target_backend;
};

struct close {
    static constexpr inline bool frontend_type = true;

    i8 type{'C'};
    be_i32 length;
    //i8 _s_to_close_a_prepared_statement_or__p_to_close_a_portal;
    //std::string the_name_of_the_prepared_statement_or_portal_to_close_an_empty_string_selects_the_unnamed_prepared_statement_or_portal_;
};

struct close_complete {
    static constexpr inline bool backend_type = true;

    i8 type{'3'};
    be_i32 length{4};
};

struct command_complete {
    static constexpr inline bool backend_type = true;

    i8 type{'C'};
    be_i32 length;
    std::string the_command_tag;
};

struct copy_data {
    static constexpr inline bool backend_type  = true;
    static constexpr inline bool frontend_type = true;

    i8 type{'d'};
    be_i32 length;
    i8 *data_that_forms_part_of_a_c_o_p_y_data_stream;
};

struct copy_done {
    static constexpr inline bool backend_type  = true;
    static constexpr inline bool frontend_type = true;

    i8 type{'c'};
    be_i32 length{4};
};

struct copy_fail {
    static constexpr inline bool frontend_type = true;

    i8 type{'f'};
    be_i32 length;
    std::string an_error_message_to_report_as_the_cause_of_failure;
};

struct copy_in_response {
    static constexpr inline bool backend_type = true;

    i8 type{'G'};
    be_i32 length;
    i8 _0_indicates_the_overall_c_o_p_y_format_is_textual_rows_separated_by_newlines_columns_separated_by_separator_characters_etc;
    i16 the_number_of_columns_in_the_data_to_be_copied_denoted_n_below_;
    i16 the_format_codes_to_be_used_for_each_column;
};

struct copy_out_response {
    static constexpr inline bool backend_type = true;

    i8 type{'H'};
    be_i32 length;
    i8 _0_indicates_the_overall_c_o_p_y_format_is_textual_rows_separated_by_newlines_columns_separated_by_separator_characters_etc;
    i16 the_number_of_columns_in_the_data_to_be_copied_denoted_n_below_;
    i16 the_format_codes_to_be_used_for_each_column;
};

struct copy_both_response {
    static constexpr inline bool backend_type = true;

    i8 type{'W'};
    be_i32 length;
    i8 _0_indicates_the_overall_c_o_p_y_format_is_textual_rows_separated_by_newlines_columns_separated_by_separator_characters_etc;
    i16 the_number_of_columns_in_the_data_to_be_copied_denoted_n_below_;
    i16 the_format_codes_to_be_used_for_each_column;
};

struct data_row {
    static constexpr inline bool backend_type = true;

    i8 type{'D'};
    be_i32 length;
    i16 the_number_of_column_values_that_follow_possibly_zero_;
    i32 the_length_of_the_column_value_in_bytes_this_count_does_not_include_itself_;
    i8 *the_value_of_the_column_in_the_format_indicated_by_the_associated_format_code;
};

struct describe {
    static constexpr inline bool frontend_type = true;

    i8 type{'D'};
    be_i32 length;
    //i8 _s_to_describe_a_prepared_statement_or__p_to_describe_a_portal;
    //std::string the_name_of_the_prepared_statement_or_portal_to_describe_an_empty_string_selects_the_unnamed_prepared_statement_or_portal_;
};

struct empty_query_response {
    static constexpr inline bool backend_type = true;

    i8 type{'I'};
    be_i32 length{4};
};

// https://www.postgresql.org/docs/current/protocol-error-fields.html
struct error_response {
    static constexpr inline bool backend_type = true;

    i8 type{'E'};
    be_i32 length;
    //i8 a_code_identifying_the_field_type_if_zero_this_is_the_message_terminator_and_no_string_follows;
    //std::string the_field_value;

    struct error1 {
        std::string_view severity_localized;
        std::string_view severity;
        std::string_view code;
        std::string_view message;
        std::string_view detail;
        std::string_view hint;
        std::string_view position;
        std::string_view internal_position;
        std::string_view internal_query;
        std::string_view where;
        std::string_view schema;
        std::string_view table;
        std::string_view column;
        std::string_view data_type;
        std::string_view constraint;
        std::string_view file;
        std::string_view line;
        std::string_view routine;

        std::string format() const {
            return std::format("{}: {}: {}: {}\n{}:{}: {}()", severity, code, message, detail, file, line, routine);
        }
    };

    auto error() const {
        auto base = (const char *)&length + sizeof(length);
        error1 e;
        while (*base) {
            auto code = *base++;
            std::string_view sv{base};
            switch (code) {
                case 'S': e.severity_localized = sv; break;
                case 'V': e.severity = sv; break;
                case 'C': e.code = sv; break;
                case 'M': e.message = sv; break;
                case 'D': e.detail = sv; break;
                case 'H': e.hint = sv; break;
                case 'P': e.position = sv; break;
                case 'p': e.internal_position = sv; break;
                case 'q': e.internal_query = sv; break;
                case 'W': e.where = sv; break;
                case 's': e.schema = sv; break;
                case 't': e.table = sv; break;
                case 'c': e.column = sv; break;
                case 'd': e.data_type = sv; break;
                case 'n': e.constraint = sv; break;
                case 'F': e.file = sv; break;
                case 'L': e.line = sv; break;
                case 'R': e.routine = sv; break;
                default: break;
            }
            base += sv.size() + 1;
        }
        return e;
    }
};

struct execute {
    static constexpr inline bool frontend_type = true;

    i8 type{'E'};
    be_i32 length;
    //std::string the_name_of_the_portal_to_execute_an_empty_string_selects_the_unnamed_portal_;
    //i32 maximum_number_of_rows_to_return_if_portal_contains_a_query_that_returns_rows_ignored_otherwise_;
};

struct flush {
    static constexpr inline bool frontend_type = true;

    i8 type{'H'};
    be_i32 length{4};
};

struct function_call {
    static constexpr inline bool frontend_type = true;

    i8 type{'F'};
    be_i32 length;
    i32 specifies_the_object_id_of_the_function_to_call;
    i16 the_number_of_argument_format_codes_that_follow_denoted_c_below_;
    i16 the_argument_format_codes;
    i16 specifies_the_number_of_arguments_being_supplied_to_the_function;
    i32 the_length_of_the_argument_value_in_bytes_this_count_does_not_include_itself_;
    i8 *the_value_of_the_argument_in_the_format_indicated_by_the_associated_format_code;
    i16 the_format_code_for_the_function_result;
};

struct function_call_response {
    static constexpr inline bool backend_type = true;

    i8 type{'V'};
    be_i32 length;
    i32 the_length_of_the_function_result_value_in_bytes_this_count_does_not_include_itself_;
    i8 *the_value_of_the_function_result_in_the_format_indicated_by_the_associated_format_code;
};

struct gssenc_request {
    static constexpr inline bool frontend_type = true;

    be_i32 length{8};
    i32 the_gssapi_encryption_request_code{80877104};
};

struct gss_response {
    static constexpr inline bool frontend_type = true;

    i8 type{'p'};
    be_i32 length;
    i8 *gssapi_sspi_specific_message_data;
};

struct negotiate_protocol_version {
    static constexpr inline bool backend_type = true;

    i8 type{'v'};
    be_i32 length;
    i32 newest_minor_protocol_version_supported_by_the_server_for_the_major_protocol_version_requested_by_the_client;
    i32 number_of_protocol_options_not_recognized_by_the_server;
    std::string the_option_name;
};

struct no_data {
    static constexpr inline bool backend_type = true;

    i8 type{'n'};
    be_i32 length{4};
};

struct notice_response {
    static constexpr inline bool backend_type = true;

    i8 type{'N'};
    be_i32 length;
    i8 a_code_identifying_the_field_type_if_zero_this_is_the_message_terminator_and_no_string_follows;
    std::string the_field_value;
};

struct notification_response {
    static constexpr inline bool backend_type = true;

    i8 type{'A'};
    be_i32 length;
    i32 the_process_id_of_the_notifying_backend_process;
    std::string the_name_of_the_channel_that_the_notify_has_been_raised_on;
    std::string the__payload__string_passed_from_the_notifying_process;
};

struct parameter_description {
    static constexpr inline bool backend_type = true;

    i8 type{'t'};
    be_i32 length;
    i16 the_number_of_parameters_used_by_the_statement_can_be_zero_;
    i32 specifies_the_object_id_of_the_parameter_data_type;
};

struct parameter_status {
    static constexpr inline bool backend_type = true;

    i8 type{'S'};
    be_i32 length;
    std::string the_name_of_the_run_time_parameter_being_reported;
    std::string the_current_value_of_the_parameter;
};

struct parse {
    static constexpr inline bool frontend_type = true;

    i8 type{'P'};
    be_i32 length;
    //std::string the_name_of_the_destination_prepared_statement_an_empty_string_selects_the_unnamed_prepared_statement_;
    //std::string the_query_string_to_be_parsed;
    //i16 the_number_of_parameter_data_types_specified_can_be_zero_;
    //i32 specifies_the_object_id_of_the_parameter_data_type;
};

struct parse_complete {
    static constexpr inline bool backend_type = true;

    i8 type{'1'};
    be_i32 length{4};
};

struct password_message {
    static constexpr inline bool frontend_type = true;

    i8 type{'p'};
    be_i32 length;
    std::string the_password_encrypted_if_requested_;
};

struct portal_suspended {
    static constexpr inline bool backend_type = true;

    i8 type{'s'};
    be_i32 length{4};
};

struct query {
    static constexpr inline bool frontend_type = true;

    i8 type{'Q'};
    be_i32 length;
    //std::string the_query_string_itself;
};

struct ready_for_query {
    static constexpr inline bool backend_type = true;

    i8 type{'Z'};
    be_i32 length{5};
    i8 current_backend_transaction_status_indicator;
};

struct row_description {
    static constexpr inline bool backend_type = true;

    i8 type{'T'};
    be_i32 length;
    //i16 specifies_the_number_of_fields_in_a_row_can_be_zero_;
    //std::string the_field_name;
    //i32 if_the_field_can_be_identified_as_a_column_of_a_specific_table_the_object_id_of_the_table_otherwise_zero;
    //i16 if_the_field_can_be_identified_as_a_column_of_a_specific_table_the_attribute_number_of_the_column_otherwise_zero;
    //i32 the_object_id_of_the_field_s_data_type;
    //i16 the_data_type_size_see_pg_type;
    //i32 the_type_modifier_see_pg_attribute;
    //i16 the_format_code_being_used_for_the_field;
};

struct sasl_initial_response {
    static constexpr inline bool frontend_type = true;

    i8 type{'p'};
    be_i32 length;
    //std::string name_of_the_sasl_authentication_mechanism_that_the_client_selected;
    //be_i32 length2;
    //i8 *sasl_mechanism_specific__initial_response_;
};

struct sasl_response {
    static constexpr inline bool frontend_type = true;

    i8 type{'p'};
    be_i32 length;
    //i8 *sasl_mechanism_specific_message_data;
};

struct ssl_request {
    static constexpr inline bool frontend_type = true;

    be_i32 length{8};
    i32 the_ssl_request_code{80877103};
};

struct startup_message {
    static constexpr inline bool frontend_type = true;

    be_i32 length;
    be_i32 the_protocol_version_number{0x030000};
    //std::string the_parameter_name;
    //std::string the_parameter_value;
};

struct sync {
    static constexpr inline bool frontend_type = true;

    i8 type{'S'};
    be_i32 length{4};
};

struct terminate {
    static constexpr inline bool frontend_type = true;

    i8 type{'X'};
    be_i32 length{4};
};

#pragma pack(pop)
