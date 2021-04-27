package ca.mcgill.sis.dmas.kam1n0.utils.src;

import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;

import java.util.Calendar;
import java.util.Date;

import static org.apache.commons.lang3.time.DateUtils.MILLIS_PER_MINUTE;
import static org.apache.commons.lang3.time.DateUtils.MILLIS_PER_SECOND;

public class FormatMilliseconds {
    public static String ToReadableTime(long milliseconds) {
        if (milliseconds >= MILLIS_PER_SECOND) {
            String millis = DurationFormatUtils.formatDurationWords(milliseconds, true, true);

            if (milliseconds < MILLIS_PER_MINUTE) {
                long millisecondLeft = DateUtils.getFragmentInMilliseconds(new Date(milliseconds), Calendar.SECOND);
                if (millisecondLeft > 0)
                    millis = millis + " " + AddMillisecondPrefix(millisecondLeft);
            }
            return millis;
        }
        else
            return AddMillisecondPrefix(milliseconds);
    }

    private static String AddMillisecondPrefix(long millisecond) {
        return millisecond + " millisecond" + (millisecond > 1 ? "s" : "");
    }
}
