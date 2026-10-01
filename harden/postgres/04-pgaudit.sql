-- database: clinic
-- The extension can only be created once the library is preloaded, i.e. after the restart; the first pass skips it.
DO $$
BEGIN
    IF 'pgaudit' = ANY (string_to_array(replace(current_setting('shared_preload_libraries'), ' ', ''), ',')) THEN
        CREATE EXTENSION IF NOT EXISTS pgaudit;
    END IF;
END $$;
