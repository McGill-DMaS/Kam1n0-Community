package ca.mcgill.sis.dmas.kam1n0.utils.src;

import static org.junit.Assert.*;
import org.junit.Test;

public class TestFormatMilliseconds {
    @Test
    public void When_smaller_then_one_second_ToReadableTime_is_only_millisecond() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(999).equals("999 milliseconds"));
    }

    @Test
    public void When_exactly_one_millisecond_ToReadableTime_millisecond_is_singular() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(1).equals("1 millisecond"));
    }

    @Test
    public void When_smaller_then_one_minute_ToReadableTime_is_second_and_millisecond() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(58222).equals("58 seconds 222 milliseconds"));
    }

    public void When_smaller_then_one_minute_with_exactly_one_milliseconde_ToReadableTime_is_second_and_millisecond_is_singular() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(38001).equals("38 seconds 1 millisecond"));
    }

    @Test
    public void When_exactly_one_second_ToReadableTime_second_is_singular() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(1000).equals("1 second"));
    }

    @Test
    public void When_exactly_one_minute_ToReadableTime_is_only_minute() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(60000).equals("1 minute"));
    }

    @Test
    public void When_exactly_two_second_ToReadableTime_second_is_plural() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(2000).equals("2 seconds"));
    }

    @Test
    public void When_exactly_one_hour_ToReadableTime_is_only_hour_and_singular() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(3600000).equals("1 hour"));
    }

    @Test
    public void When_exactly_two_hour_ToReadableTime_is_only_hour_and_plural() throws Exception {
        assertTrue(FormatMilliseconds.ToReadableTime(7200000).equals("2 hours"));
    }
}