/**
 * Copyright © 2021 Jeremy Custenborder (jcustenborder@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.jcustenborder.kafka.config.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.response.LookupResponse;
import com.github.jcustenborder.kafka.config.vault.VaultConfigProviderConfig.VaultLoginBy;
import com.github.jcustenborder.kafka.connect.utils.config.Description;
import com.google.common.base.Strings;

import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.apache.kafka.connect.errors.ConnectException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.nio.file.Files;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Description("This config provider is used to retrieve configuration settings from a Hashicorp vault instance. " +
    "Config providers are generic and can be used in any application that utilized the Kafka AbstractConfig class. ")
public class VaultConfigProvider implements ConfigProvider {
  private static final Logger log = LoggerFactory.getLogger(VaultConfigProvider.class);
  private final AtomicReference<TokenMetadata> tokenMetadata = new AtomicReference<>(
    new TokenMetadata(null)
  );
  VaultConfigProviderConfig config;
  Vault vault;
  KubernetesAuth kubernetesAuth;


  @Override
  public ConfigData get(String path) {
    return get(path, Collections.emptySet());
  }

  @Override
  public ConfigData get(String path, Set<String> keys) {
    log.info("get() - path = '{}' keys = '{}'", path, keys);
    try {
      LogicalResponse logicalResponse = this.vault.withRetries(this.config.maxRetries, this.config.retryInterval)
          .logical()
          .read(path);
      if (logicalResponse.getRestResponse().getStatus() == 200) {
        Predicate<Map.Entry<String, String>> filter = keys == null || keys.isEmpty() ?
            entry -> true : entry -> keys.contains(entry.getKey());
        Map<String, String> result = logicalResponse.getData()
            .entrySet()
            .stream()
            .filter(filter)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        Long ttl = logicalResponse.getLeaseDuration();
        if (ttl == null || ttl <= 0) {
          ttl = config.minimumSecretTTL;
        }
        return new ConfigData(result, ttl);
      } else {
        throw new ConfigException(
            String.format("Vault path '%s' was not found", path)
        );
      }
    } catch (VaultException e) {
      ConfigException configException = new ConfigException(
          String.format("Exception thrown reading from '%s'", path)
      );
      configException.initCause(e);
      throw configException;
    }
  }


  @Override
  public void close() throws IOException {

  }


  @Override
  public void configure(Map<String, ?> settings) {
    this.config = new VaultConfigProviderConfig(settings);
    configureVault();

    AuthHandlers.AuthHandler authHandler = AuthHandlers.getHandler(this.config.loginBy);
    AuthHandlers.AuthConfig authConfig;

    try {
      authConfig = authHandler.auth(this.config, this.vault);
    } catch (VaultException ex) {
      throw new ConnectException(
          "Exception while authenticating to Vault",
          ex
      );
    }
    log.trace("authConfig = {}", authConfig);
  }

  private LocalDateTime getTokenExpirationTime() throws VaultException {
    Long hardRenewThreshold = 5L;
    LookupResponse lookupResponse = vault.auth().lookupSelf();
    long creationTtlInSec = lookupResponse.getCreationTTL() != 0L ? lookupResponse.getCreationTTL() : lookupResponse.getTTL();
    return LocalDateTime.now().plusSeconds(creationTtlInSec - hardRenewThreshold);
  }

  private static String getJWT(String path) throws ConfigException {
    try {
      Path file = Paths.get(path);
      String jwt = new String(Files.readAllBytes(file));
      if (Strings.isNullOrEmpty(jwt)) {
        throw new Exception(String.format("JWT token from file is invalid (%s)", jwt));
      }
      return jwt;
    } catch (Exception ex) {
      ConfigException configException = new ConfigException(
        String.format("Could not load JWT token from file", ex)
      );
      configException.initCause(ex);
      throw configException;
    }
  }

  private void configureVault() {
    VaultConfig config = this.config.createConfig();
    this.vault = new Vault(config);

    try {
      if (this.config.loginBy == VaultLoginBy.Kubernetes) {
        String role = this.config.role;
        String jwt = getJWT(this.config.jwtPath);
        this.kubernetesAuth = new KubernetesAuth(this.vault, role, jwt);
        String kubernetesAuthToken = this.kubernetesAuth.getToken();
        config.token(kubernetesAuthToken);
        this.tokenMetadata.set(new TokenMetadata(getTokenExpirationTime()));
      }
    } catch (Exception ex) {
      ConfigException configException = new ConfigException(
          String.format("Could not configure vault with Kubernetes Authentication", ex)
      );
      configException.initCause(ex);
      throw configException;
    }
  }

  public static ConfigDef config() {
    return VaultConfigProviderConfig.config();
  }

  private static class TokenMetadata {

    private final LocalDateTime tokenExpirationTime;

    public LocalDateTime getExpirationTime() {
        return this.tokenExpirationTime;
    }

      public TokenMetadata(LocalDateTime tokenExpirationTime) {
        this.tokenExpirationTime = tokenExpirationTime;
    }
  }
}
