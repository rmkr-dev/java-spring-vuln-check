package hawk.interceptor;

import hawk.context.TenantContext;
import hawk.entity.TenantSupport;
import org.hibernate.Interceptor;
import org.hibernate.type.Type;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.Serializable;

@Configuration
public class DBInterceptor {

    @Bean
    public Interceptor hibernateInterceptor() {
        return new Interceptor() {
            @Override
            public void onDelete(Object entity, Object id, Object[] state, String[] propertyNames, Type[] types) {
                if (entity instanceof TenantSupport) {
                    ((TenantSupport) entity).setTenantId(TenantContext.getCurrentTenant());
                }
            }

            @Override
            public boolean onFlushDirty(
                    Object entity,
                    Object id,
                    Object[] currentState,
                    Object[] previousState,
                    String[] propertyNames,
                    Type[] types) {
                if (entity instanceof TenantSupport) {
                    ((TenantSupport) entity).setTenantId(TenantContext.getCurrentTenant());
                }
                return false;
            }

            @Override
            public boolean onSave(Object entity, Object id, Object[] state, String[] propertyNames, Type[] types) {
                if (entity instanceof TenantSupport) {
                    ((TenantSupport) entity).setTenantId(TenantContext.getCurrentTenant());
                }
                return false;
            }
        };
    }

    @Bean
    public HibernatePropertiesCustomizer hibernatePropertiesCustomizer(Interceptor hibernateInterceptor) {
        return hibernateProperties -> hibernateProperties.put("hibernate.session_factory.interceptor", hibernateInterceptor);
    }
}
