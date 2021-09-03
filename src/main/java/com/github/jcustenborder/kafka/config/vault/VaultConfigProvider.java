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
import com.bettercloud.vault.response.AuthResponse;
import com.bettercloud.vault.response.LogicalResponse;
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

import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;

import java.time.LocalDateTime;
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
  private static final AtomicReference<TokenMetadata> TOKEN_METADATA = new AtomicReference<>(new TokenMetadata(null, LocalDateTime.now()));

  VaultConfigProviderConfig vaultConfigProviderConfig;
  Vault vault;
  VaultConfig vaultConfig;

  @Override
  public ConfigData get(String path) {
    return get(path, Collections.emptySet());
  }

  @Override
  public ConfigData get(String path, Set<String> keys) {
    ensureVaultIsAuthenticated();

    if (Strings.isNullOrEmpty(path)) {
      log.warn("Vault path '{}'' is not set or empty", path);
      return new ConfigData(Collections.emptyMap());
    }

    log.info("get() - path = '{}' keys = '{}'", path, keys);
    try {
      LogicalResponse logicalResponse = this.vault.withRetries(this.vaultConfigProviderConfig.maxRetries, this.vaultConfigProviderConfig.retryInterval).logical().read(path);
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
          ttl = vaultConfigProviderConfig.minimumSecretTTL;
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
  public void close() throws IOException {}


  @Override
  public void configure(Map<String, ?> settings) {
    this.vaultConfigProviderConfig = new VaultConfigProviderConfig(settings);
    buildVault();
    ensureVaultIsAuthenticated();

    AuthHandlers.AuthHandler authHandler = AuthHandlers.getHandler(this.vaultConfigProviderConfig.loginBy);
    AuthHandlers.AuthConfig authConfig;

    try {
      authConfig = authHandler.auth(this.vaultConfigProviderConfig, this.vault);
    } catch (VaultException ex) {
      throw new ConnectException(
          "Exception while authenticating to Vault",
          ex
      );
    }
    log.trace("authConfig = {}", authConfig);
  }

  private void buildVault() {
    this.vaultConfig = vaultConfigProviderConfig.createConfig();

    String token = TOKEN_METADATA.get().getToken();
    log.info("DEBUGGING: buildVault.token: '{}'", token);
    if (!Strings.isNullOrEmpty(token)) {
      log.info("DEBUGGING: Using token saved in metadata");
      this.vaultConfig.token(token);
    }

    this.vault = new Vault(this.vaultConfig);
  }

  private boolean isTokenValid() {
    log.info("Checking if token is valid");
    String token = TOKEN_METADATA.get().getToken();
    LocalDateTime tokenExpiryTime = TOKEN_METADATA.get().getTokenExpirationTime();

    log.info("DEBUGGING: isTokenValid.token: '{}'", token);
    log.info("DEBUGGING: isTokenValid.tokenExpiryTime: '{}'", tokenExpiryTime);

    if (Strings.isNullOrEmpty(token)) return false;
    
    if (tokenExpiryTime == null) return false;
    
    return LocalDateTime.now().isBefore(tokenExpiryTime);
  }

  private TokenMetadata renewKubernetesToken() throws RuntimeException {
    log.info("Renewing Kubernetes Token");

    try {
      String jwt = getJWTFromFile(this.vaultConfigProviderConfig.jwtPath);
      AuthResponse authResponse = vault.auth().loginByKubernetes(this.vaultConfigProviderConfig.role, jwt);
      // return vault.auth().loginByKubernetes(this.vaultConfigProviderConfig.role, jwt).getAuthClientToken();
      String token = authResponse.getAuthClientToken();
      LocalDateTime tokenExpirationTime = LocalDateTime.now().plusSeconds(authResponse.getAuthLeaseDuration() - this.vaultConfigProviderConfig.tokenRenewThreshold);
      this.vaultConfig.token(token);
      this.vault = new Vault(this.vaultConfig);
      return new TokenMetadata(token, tokenExpirationTime);
      // vaultConfig.token(renewedToken);
      // this.vault = new Vault(vaultConfig);
      // log.info("DEBUGGING: renewKubernetesToken.vaultConfig.token: '{}'", vaultConfig.getToken());
      // LocalDateTime tokenExpiryTime = getTokenExpirationTime();
      // TOKEN_METADATA.updateAndGet(old -> new TokenMetadata(renewedToken, tokenExpiryTime));
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  private void ensureVaultIsAuthenticated() throws RuntimeException {
    log.info("Ensuring Vault is authenticated");
    if (this.vault == null) throw new RuntimeException("Vault is not configured");

    log.info("DEBUGGING: ensureVaultIsAuthenticated.vaultConfig.token '{}'", vaultConfig.getToken());
    if (isTokenValid()) {
      log.info("DEBUGGING: Token is valid");
      return;
    }
    
    // String token = TOKEN_METADATA.get().getToken();
    // LocalDateTime tokenExpiryTime = TOKEN_METADATA.get().getTokenExpirationTime();

    // log.info("DEBUGGING: ensureVaultIsAuthenticated.token: '{}'", token);
    // log.info("DEBUGGING: ensureVaultIsAuthenticated.tokenExpiryTime: '{}'", tokenExpiryTime);

    // try {
      // if (this.vaultConfigProviderConfig.loginBy == VaultLoginBy.Token) renewToken();
    if (this.vaultConfigProviderConfig.loginBy == VaultLoginBy.Kubernetes) {
      log.info("DEBUGGING: Fetching new k8s token");
      // TOKEN_METADATA.updateAndGet(old -> new TokenMetadata(renewKubernetesToken(), getTokenExpirationTime()));
      TOKEN_METADATA.updateAndGet(old -> renewKubernetesToken());
    }
    // } catch (VaultException ex) {
    //   throw new RuntimeException(ex);
    // }
  }

  private String getJWTFromFile(String path) throws Exception {
    log.info("Reading JWT token from '{}'", path);
    try {
      Path file = Paths.get(path);
      return new String(Files.readAllBytes(file));
    } catch (IOException | InvalidPathException ex) {
      throw ex;
    }
  }

  public static ConfigDef config() {
    return VaultConfigProviderConfig.config();
  }

  private static class TokenMetadata {
    private final String token;
    private final LocalDateTime tokenExpirationTime;

    public TokenMetadata(String token, LocalDateTime tokenExpirationTime) {
      this.token = token;
      this.tokenExpirationTime = tokenExpirationTime;
    }

    public LocalDateTime getTokenExpirationTime() {
      return this.tokenExpirationTime;
    }

    public String getToken() {
      return this.token;
    }
  }
}
