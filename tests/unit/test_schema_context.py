import pytest

from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable


def sample_schema():
    return SchemaContext(
        dialect="postgres",
        tables=(
            SchemaTable(
                name="orders",
                columns=(
                    SchemaColumn("id", "integer"),
                    SchemaColumn("customer_id", "integer"),
                    SchemaColumn("total", "numeric"),
                ),
            ),
        ),
    )


def test_schema_context_renders_deterministically():
    expected = (
        "Database dialect: postgres\n"
        "Table: orders\n"
        "  - id: integer\n"
        "  - customer_id: integer\n"
        "  - total: numeric"
    )
    assert sample_schema().to_prompt_text() == expected
    assert sample_schema().to_prompt_text() == expected


@pytest.mark.parametrize("name", ["", "   "])
def test_schema_column_rejects_empty_name(name):
    with pytest.raises(ValueError, match="column name"):
        SchemaColumn(name, "integer")


def test_schema_column_rejects_empty_type():
    with pytest.raises(ValueError, match="data type"):
        SchemaColumn("id", " ")


def test_schema_table_requires_columns():
    with pytest.raises(ValueError, match="at least one column"):
        SchemaTable("orders", ())


def test_schema_table_rejects_duplicate_columns_case_insensitively():
    with pytest.raises(ValueError, match="duplicate columns"):
        SchemaTable("orders", (SchemaColumn("ID", "integer"), SchemaColumn("id", "text")))


def test_schema_context_requires_tables():
    with pytest.raises(ValueError, match="at least one table"):
        SchemaContext(tables=())


def test_schema_context_rejects_duplicate_tables_case_insensitively():
    with pytest.raises(ValueError, match="duplicate table"):
        SchemaContext(
            tables=(
                SchemaTable("orders", (SchemaColumn("id", "integer"),)),
                SchemaTable("ORDERS", (SchemaColumn("id", "integer"),)),
            )
        )
