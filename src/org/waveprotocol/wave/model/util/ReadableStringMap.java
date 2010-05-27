// Copyright 2009 Google Inc. All Rights Reserved.

package org.waveprotocol.wave.model.util;

/**
 * A read-only interface to a map of strings to V.
 *
 * We define this in favor of using a java.util collections interface so that we
 * can write an optimized implementation for GWT.
 *
 * Null is not permitted as a key. All methods, even
 * {@link #containsKey(String)} will reject null keys.
 *
 * Implementations must distinguish between null values and unset keys.
 *
 * @author ohler@google.com (Christian Ohler)
 *
 * @param <V> type of values in the map
 */
public interface ReadableStringMap<V> {
  // Maybe add a primitive hasEntry(key, value) that returns true if an
  // entry for the key exists AND the value is equal to value.

  /**
   * A procedure that accepts a key and the corresponding value from the map.
   */
  public interface ProcV<V> {
    public void apply(String key, V value);
  }

  /**
   * Return the value associated with key.  Must only be called if there
   * is one.
   */
  V getExisting(String key);

  /**
   * Return the value associated with key, or defaultValue if there is none.
   */
  V get(String key, V defaultValue);

  /**
   * Return the value associated with key, or null if there is none
   */
  V get(String key);

  /**
   * Return true iff this map contains a value for the key key.
   */
  boolean containsKey(String key);

  /**
   * @return some key in the map. If the map is empty, null is returned.
   */
  String someKey();

  /**
   * Return true iff this map does not contain a value for any key.
   */
  boolean isEmpty();

  /**
   * Call the callback for every key-value pair in the map, in undefined
   * order.
   */
  void each(ProcV<? super V> callback);

  /**
   * Count the number of key-value pairs in the map.
   *
   * Note: Depending on the underlying map implementation, this may be a
   * time-consuming operation.
   */
  int countEntries();

  /**
   * @return a live, unmodifiable view of the keys, as a set. If the map is
   *         modified while iterating over the key set, the result is undefined.
   */
  ReadableStringSet keySet();
}