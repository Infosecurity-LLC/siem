package ru.gkis.soc.siem.enricher.cache.radixtree;

import com.google.common.net.InetAddresses;

import java.io.Serializable;
import java.net.InetAddress;

abstract class AbstractRadixTree<KV> implements Serializable {
    /**
     * Special value that designates that there are no value stored in the key so far.
     * One can't use store value in a tree.
     */
    protected static final int NULL_PTR = -1;
    protected static final int ROOT_PTR = 0;

    protected static final char NET_MASK_SPLIT = '/';

    protected int[] rights;
    protected int[] lefts;
    protected long[] values;
    protected int allocatedSize;
    protected int size;

    public static final long NO_VALUE = -1;

    /**
     * Initialize the size of the tree allocation.
     *
     * @param allocatedSize size
     */
    protected void init(int allocatedSize) {
        this.allocatedSize = allocatedSize;

        rights = new int[this.allocatedSize];
        lefts = new int[this.allocatedSize];
        values = new long[this.allocatedSize];

        size = 1;
        lefts[0] = NULL_PTR;
        rights[0] = NULL_PTR;
        values[0] = NO_VALUE;
    }

    public abstract void put(KV key, KV mask, long value);

    /**
     * Expand Allocated Size
     */
    protected void expandAllocatedSize() {
        int oldSize = allocatedSize;
        allocatedSize *= 2;

        int[] newLefts = new int[allocatedSize];
        System.arraycopy(lefts, 0, newLefts, 0, oldSize);
        lefts = newLefts;

        int[] newRights = new int[allocatedSize];
        System.arraycopy(rights, 0, newRights, 0, oldSize);
        rights = newRights;

        long[] newValues = new long[allocatedSize];
        System.arraycopy(values, 0, newValues, 0, oldSize);
        values = newValues;
    }

    public abstract long selectValue(KV key);

    public void put(String ipNet, long value) {
        int pos = ipNet.indexOf(NET_MASK_SPLIT);
        String ipStr = ipNet.substring(0, pos);
        put(InetAddresses.forString(ipStr), ipNet.substring(pos + 1), value);
    }

    public abstract void put(InetAddress address, String netMaskStr, long value);

    public long selectValue(String ipStr) {
        return selectValue(ipToKey(ipStr));
    }

    public abstract long selectValue(InetAddress ip);

    protected abstract KV ipToKey(String ip);

    public int getSize() {
        return size;
    }

    public int getAllocatedSize() {
        return allocatedSize;
    }

    public int getValuesSize() {
        return values == null ? -1 : values.length;
    }
}
