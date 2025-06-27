/*
  This file is a part of Angry IP Scanner source code,
  see http://www.angryip.org/ for more information.
  Licensed under GPLv2.
 */

package net.azib.ipscan.util;

import java.util.Iterator;

/**
 * SequenceIterator - joins several iterators together to provide a seamless iteration.
 *
 * @author Anton Keks
 */
public class SequenceIterator<E> implements Iterator<E> {
       private final Iterator<E>[] iterators;
       int currentIndex = 0;
	
       @SafeVarargs
       public SequenceIterator(Iterator<E>... iterators) {
               this.iterators = iterators;

               // check that at least one iterator has elements
               boolean any = false;
               for (Iterator<E> it : iterators) {
                       if (it.hasNext()) { any = true; break; }
               }
               if (!any)
                       throw new IllegalArgumentException();
       }

       public boolean hasNext() {
               shiftToNextAvailable();
               return currentIndex < iterators.length;
       }

       public E next() {
               shiftToNextAvailable();
               return iterators[currentIndex].next();
       }

       private void shiftToNextAvailable() {
               while (currentIndex < iterators.length && !iterators[currentIndex].hasNext()) {
                       currentIndex++;
               }
       }

	public void remove() {
		iterators[currentIndex].remove();
	}
}
