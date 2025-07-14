package com.oneaccess.auth.entities.common;

import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.*;

import java.io.Serializable;

@MappedSuperclass
@Getter
@Setter
public abstract class AbstractGenericPrimaryKey<PK> implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @jakarta.annotation.Nullable
    @Column(name = "id", nullable = false)
    private PK id;

}
