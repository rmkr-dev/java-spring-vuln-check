package hawk.entity;

import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.io.Serializable;

@Entity
@Table(name = "user", schema = "public")
@FilterDef(name = "tenantFilter", parameters = {@ParamDef(name = "tenantId", type = String.class)})
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class User implements TenantSupport, Serializable {
    private static final long serialVersionUID = -6986746375915710855L;
    @Id
    @GeneratedValue(strategy= GenerationType.AUTO)
    private Long id;
    private String name;
    private String description;
    @Column(name = "tenant_id")
    private String tenantId;

    protected User() {}

    public User(Long id, String name, String description, String tenantId) {
        this(name, description, tenantId);
        this.id = id;
    }

    public User(String name, String description, String tenantId) {
        this.name = name;
        this.description = description;
        this.tenantId = tenantId;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getTenantId() {
        return tenantId;
    }


    @Override
    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }
}
