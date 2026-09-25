class SiteService:
    def __init__(self, site_repo, device_repo):
        self.site_repo = site_repo
        self.device_repo = device_repo

    def list_sites(self):
        return self.site_repo.get_all()

    def get_site(self, site_id):
        return self.site_repo.get_by_id(site_id)

    def create_site(self, name, description="", address_reference=""):
        name_clean = name.strip()
        if not name_clean:
            raise ValueError("El nombre de la sede es obligatorio.")
        return self.site_repo.create(name_clean, description.strip(), address_reference.strip())

    def update_site(self, site_id, name, description="", address_reference=""):
        name_clean = name.strip()
        if not name_clean:
            raise ValueError("El nombre de la sede no puede estar vacío.")
        return self.site_repo.update(site_id, name_clean, description.strip(), address_reference.strip())

    def delete_site(self, site_id):
        return self.site_repo.delete(site_id)
