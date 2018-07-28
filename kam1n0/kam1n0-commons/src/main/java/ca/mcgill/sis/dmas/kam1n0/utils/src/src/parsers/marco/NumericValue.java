/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco;

import java.math.BigDecimal;
import java.math.BigInteger;
import javax.annotation.CheckForNull;
import javax.annotation.CheckForSigned;
import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;

public class NumericValue extends Number {

    public static final int F_UNSIGNED = 1;
    public static final int F_INT = 2;
    public static final int F_LONG = 4;
    public static final int F_LONGLONG = 8;
    public static final int F_FLOAT = 16;
    public static final int F_DOUBLE = 32;

    public static final int FF_SIZE = F_INT | F_LONG | F_LONGLONG | F_FLOAT | F_DOUBLE;

    private final int base;
    private final String integer;
    private String fraction;
    private int expbase = 0;
    private String exponent;
    private int flags;

    public NumericValue(int base, String integer) {
        this.base = base;
        this.integer = integer;
    }

    @Nonnegative
    public int getBase() {
        return base;
    }

    @Nonnull
    public String getIntegerPart() {
        return integer;
    }

    @CheckForNull
    public String getFractionalPart() {
        return fraction;
    }

    /* pp */ void setFractionalPart(String fraction) {
        this.fraction = fraction;
    }

    @CheckForSigned
    public int getExponentBase() {
        return expbase;
    }

    @CheckForNull
    public String getExponent() {
        return exponent;
    }

    /* pp */ void setExponent(int expbase, String exponent) {
        this.expbase = expbase;
        this.exponent = exponent;
    }

    public int getFlags() {
        return flags;
    }

    /* pp */ void setFlags(int flags) {
        this.flags = flags;
    }

    /**
     * So, it turns out that parsing arbitrary bases into arbitrary
     * precision numbers is nontrivial, and this routine gets it wrong
     * in many important cases.
     */
    @Nonnull
    public BigDecimal toBigDecimal() {
        int scale = 0;
        String text = getIntegerPart();
        String t_fraction = getFractionalPart();
        if (t_fraction != null) {
            text += getFractionalPart();
            // XXX Wrong for anything but base 10.
            scale += t_fraction.length();
        }
        String t_exponent = getExponent();
        if (t_exponent != null)
            scale -= Integer.parseInt(t_exponent);
        BigInteger unscaled = new BigInteger(text, getBase());
        return new BigDecimal(unscaled, scale);
    }

    @Nonnull
    public Number toJavaLangNumber() {
        int flags = getFlags();
        if ((flags & F_DOUBLE) != 0)
            return doubleValue();
        else if ((flags & F_FLOAT) != 0)
            return floatValue();
        else if ((flags & (F_LONG | F_LONGLONG)) != 0)
            return longValue();
        else if ((flags & F_INT) != 0)
            return intValue();
        else if (getFractionalPart() != null)
            return doubleValue();	// .1 is a double in Java.
        else if (getExponent() != null)
            return doubleValue();
        else
            return intValue();
    }

    private int exponentValue() {
        return Integer.parseInt(exponent, 10);
    }

    @Override
    public int intValue() {
        int v = integer.isEmpty() ? 0 : Integer.parseInt(integer, base);
        if (expbase == 2)
            v = v << exponentValue();
        else if (expbase != 0)
            v = (int) (v * Math.pow(expbase, exponentValue()));
        return v;
    }

    @Override
    public long longValue() {
        long v = integer.isEmpty() ? 0 : Long.parseLong(integer, base);
        if (expbase == 2)
            v = v << exponentValue();
        else if (expbase != 0)
            v = (long) (v * Math.pow(expbase, exponentValue()));
        return v;
    }

    @Override
    public float floatValue() {
        if (getBase() != 10)
            return longValue();
        return Float.parseFloat(toString());
    }

    @Override
    public double doubleValue() {
        if (getBase() != 10)
            return longValue();
        return Double.parseDouble(toString());
    }

    private boolean appendFlags(StringBuilder buf, String suffix, int flag) {
        if ((getFlags() & flag) != flag)
            return false;
        buf.append(suffix);
        return true;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        switch (base) {
            case 8:
                buf.append('0');
                break;
            case 10:
                break;
            case 16:
                buf.append("0x");
                break;
            case 2:
                buf.append('b');
                break;
            default:
                buf.append("[base-").append(base).append("]");
                break;
        }
        buf.append(getIntegerPart());
        if (getFractionalPart() != null)
            buf.append('.').append(getFractionalPart());
        if (getExponent() != null) {
            buf.append(base > 10 ? 'p' : 'e');
            buf.append(getExponent());
        }
        /*
         if (appendFlags(buf, "ui", F_UNSIGNED | F_INT));
         else if (appendFlags(buf, "ul", F_UNSIGNED | F_LONG));
         else if (appendFlags(buf, "ull", F_UNSIGNED | F_LONGLONG));
         else if (appendFlags(buf, "i", F_INT));
         else if (appendFlags(buf, "l", F_LONG));
         else if (appendFlags(buf, "ll", F_LONGLONG));
         else if (appendFlags(buf, "f", F_FLOAT));
         else if (appendFlags(buf, "d", F_DOUBLE));
         */
        return buf.toString();
    }
}
