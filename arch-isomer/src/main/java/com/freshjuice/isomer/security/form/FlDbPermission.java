package com.freshjuice.isomer.security.form;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.core.GrantedAuthority;

@Setter
@Builder
@Accessors(chain = true)
@NoArgsConstructor
@AllArgsConstructor
public class FlDbPermission implements GrantedAuthority {
    private String permission;

    @Override
    public String getAuthority() {
        return permission;
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) return true;
        if(o == null) return false;
        if(this.getClass() != o.getClass()) return false;
        FlDbPermission that = (FlDbPermission) o;

        boolean flag = this.permission.equals(that.permission);
        return flag;
    }

    @Override
    public int hashCode() {
        int hashCode = permission.hashCode();
        return hashCode;
    }
}
