"""ORM models.

Importing the package registers every table with Base.metadata so
`create_all` in init_db() knows the full schema regardless of import order
(evidence/audit/checkpoint/investigation are also imported lazily by managers).
"""

from app.models import audit, checkpoint, evidence, investigation  # noqa: F401