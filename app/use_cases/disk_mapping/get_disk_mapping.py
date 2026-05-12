from app.infrastructure.external_services.disk_mapping_service import collect_disk_mapping


class GetDiskMappingUseCase:
    def execute(self, root_path: str | None, max_depth: int, max_nodes: int) -> dict:
        return collect_disk_mapping(root_path=root_path, max_depth=max_depth, max_nodes=max_nodes)
