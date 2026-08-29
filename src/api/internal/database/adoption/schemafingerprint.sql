-- Describes the shape of the account schema as a sorted list of text lines.
--
-- Two databases that produce the same output hold the same tables, columns,
-- types, defaults, constraints, indexes and identity sequences, whatever order
-- the statements that built them ran in. This is what lets a database built by
-- the baseline migration and a database that was built statement by statement
-- over years be shown to be the same before one is adopted.
--
-- Migration bookkeeping tables are excluded because they differ by definition
-- between the two.
SELECT line
FROM (
    SELECT format(
        'column|%s|%s|%s|%s|%s|%s',
        relname,
        ordinal,
        attname,
        type_name,
        nullable,
        default_expression
    ) AS line
    FROM (
        SELECT
            c.relname,
            row_number() OVER (PARTITION BY c.relname ORDER BY a.attnum) AS ordinal,
            a.attname,
            format_type(a.atttypid, a.atttypmod) AS type_name,
            NOT a.attnotnull AS nullable,
            coalesce(pg_get_expr(d.adbin, d.adrelid), '') AS default_expression
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
        LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
        WHERE c.relkind = 'r'
          AND c.relname NOT IN ('goose_db_version', '_prisma_migrations')
    ) AS columns

    UNION ALL

    SELECT format('constraint|%s|%s|%s', rel.relname, con.conname, pg_get_constraintdef(con.oid)) AS line
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = rel.relnamespace AND n.nspname = 'public'
    WHERE rel.relname NOT IN ('goose_db_version', '_prisma_migrations')

    UNION ALL

    SELECT format('index|%s|%s|%s', tablename, indexname, indexdef) AS line
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename NOT IN ('goose_db_version', '_prisma_migrations')

    UNION ALL

    SELECT format('sequence|%s|%s.%s', seq.relname, tbl.relname, att.attname) AS line
    FROM pg_class seq
    JOIN pg_namespace n ON n.oid = seq.relnamespace AND n.nspname = 'public'
    JOIN pg_depend dep ON dep.objid = seq.oid AND dep.classid = 'pg_class'::regclass AND dep.deptype = 'a'
    JOIN pg_class tbl ON tbl.oid = dep.refobjid
    JOIN pg_attribute att ON att.attrelid = tbl.oid AND att.attnum = dep.refobjsubid
    WHERE seq.relkind = 'S'
) AS fingerprint
ORDER BY line;
