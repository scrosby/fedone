/**
 * Copyright 2009 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.waveprotocol.wave.model.id;

import org.waveprotocol.wave.model.id.IdSerialiser.InvalidIdException;
import org.waveprotocol.wave.model.id.IdSerialiser.RuntimeInvalidIdException;
import org.waveprotocol.wave.model.util.Preconditions;

/**
 * A wave is identified by a tuple of a wave provider domain and a local
 * identifier which is unique within the domain.
 *
 * @author zdwang@google.com (David Wang)
 * @author anorth@google.com (Alex North)
 */
public final class WaveId implements Comparable<WaveId> {

  private final String domain;
  private final String id;

  /**
   * Deserialises a wave identifier from a string, throwing a checked exception
   * if deserialisation fails.
   *
   * @param waveIdString a serialised wave id
   * @return a wave id
   * @throws InvalidIdException if the serialised form is invalid
   */
  public static WaveId checkedDeserialise(String waveIdString) throws InvalidIdException {
    return LongIdSerialiser.INSTANCE.deserialiseWaveId(waveIdString);
  }

  /**
   * Deserialises a wave identifier from a string.
   *
   * @param waveIdString a serialised wave id
   * @return a wave id
   * @throws RuntimeInvalidIdException if the serialised form is invalid
   */
  public static WaveId deserialise(String waveIdString) throws RuntimeInvalidIdException {
    try {
      return checkedDeserialise(waveIdString);
    } catch (InvalidIdException e) {
      throw new RuntimeInvalidIdException(e.getId(), e.getMessage());
    }
  }

  /**
   * Checks a string is a valid serialised wave id.
   *
   * @param waveIdString serialised wave id
   * @return the input string, for convenience
   * @throws RuntimeInvalidIdException if the string is invalid
   */
  public static String checkIsValid(String waveIdString) throws RuntimeInvalidIdException {
    deserialise(waveIdString);
    return waveIdString;
  }

  /**
   * @param domain must not be null. This is assumed to be of a valid canonical
   *        domain format.
   * @param id must not be null. This is assumed to be escaped with
   *        SimplePrefixEscaper.DEFAULT_ESCAPER.
   */
  public WaveId(String domain, String id) {
    if (domain == null || id == null) {
      Preconditions.nullPointer("Cannot create wave id with null value in [domain:"
          + domain + "] [id:" + id + "]");
    }
    if (domain.isEmpty() || id.isEmpty()) {
      Preconditions.illegalArgument("Cannot create wave id with empty value in [domain:"
          + domain + "] [id:" + id + "]");
    }

    if (SimplePrefixEscaper.DEFAULT_ESCAPER.hasEscapeCharacters(domain)) {
      Preconditions.illegalArgument(
          "Domain cannot contain characters that requires escaping: " + domain);
    }

    if (!SimplePrefixEscaper.DEFAULT_ESCAPER.isEscapedProperly(IdConstants.TOKEN_SEPARATOR, id)) {
      Preconditions.illegalArgument("Id is not properly escaped: " + id);
    }

    // Intern domain string for memory efficiency.
    // NOTE(anorth): Update equals() if interning is removed.
    this.domain = domain.intern();
    this.id = id;
  }

  /**
   * @return the domain
   */
  public String getDomain() {
    return domain;
  }

  /**
   * @return the local id
   */
  public String getId() {
    return id;
  }

  /**
   * Serialises this waveId into a unique string. For any two wave ids,
   * waveId1.serialise().equals(waveId2.serialise()) iff waveId1.equals(waveId2).
   */
  public String serialise() {
    return LongIdSerialiser.INSTANCE.serialiseWaveId(this);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + domain.hashCode();
    result = prime * result + id.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    WaveId other = (WaveId) obj;
    // Reference equality as domains are interned at construction.
    return (domain == other.domain) && id.equals(other.id);
  }

  @Override
  public String toString() {
    return "[WaveId:" + serialise() + "]";
  }

  @Override
  public int compareTo(WaveId other) {
    int domainCompare = domain.compareTo(other.domain);
    if (domainCompare == 0) {
      return id.compareTo(other.id);
    } else {
      return domainCompare;
    }
  }
}
