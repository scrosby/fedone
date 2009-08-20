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

package org.waveprotocol.wave.model.document.operation.impl;

import org.waveprotocol.wave.model.document.operation.AttributesUpdate;
import org.waveprotocol.wave.model.document.operation.util.ImmutableUpdateMap;

import java.util.List;

public class AttributesUpdateImpl
    extends ImmutableUpdateMap<AttributesUpdateImpl, AttributesUpdate>
    implements AttributesUpdate {

  public static final AttributesUpdateImpl EMPTY_MAP = new AttributesUpdateImpl();

  public AttributesUpdateImpl() {
  }

  public AttributesUpdateImpl(String ... triples) {
    super(triples);
  }

  private AttributesUpdateImpl(List<AttributeUpdate> updates) {
    super(updates);
  }

  @Override
  protected AttributesUpdateImpl createFromList(List<AttributeUpdate> updates) {
    return new AttributesUpdateImpl(updates);
  }

  public static AttributesUpdateImpl fromSortedUpdates(List<AttributeUpdate> sortedUpdates) {
    checkUpdatesSorted(sortedUpdates);
    return fromSortedUpdatesUnchecked(sortedUpdates);
  }

  public static AttributesUpdateImpl fromSortedUpdatesUnchecked(
      List<AttributeUpdate> sortedUpdates) {
    return new AttributesUpdateImpl(sortedUpdates);
  }

}
