"""Add PQC and enterprise organization fields

Revision ID: 20261116_0002
Revises: 20261107_0001
Create Date: 2026-11-16 20:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20261116_0002'
down_revision = '20261107_0001'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    
    # Helper to check if column exists
    def column_exists(table_name, column_name):
        insp = sa.inspect(conn)
        columns = [c['name'] for c in insp.get_columns(table_name)]
        return column_name in columns

    # Add organization_id to leases if not exists
    if not column_exists('leases', 'organization_id'):
        op.add_column('leases', sa.Column('organization_id', sa.String(), nullable=True))

    # Add organization_id to contracts if not exists
    if not column_exists('contracts', 'organization_id'):
        op.add_column('contracts', sa.Column('organization_id', sa.String(), nullable=True))

    # Add organization_id to tasks if not exists
    if not column_exists('tasks', 'organization_id'):
        op.add_column('tasks', sa.Column('organization_id', sa.String(), nullable=True))

    # Add organization_id to workflows if not exists
    if not column_exists('workflows', 'organization_id'):
        op.add_column('workflows', sa.Column('organization_id', sa.String(), nullable=True))


def downgrade():
    pass

