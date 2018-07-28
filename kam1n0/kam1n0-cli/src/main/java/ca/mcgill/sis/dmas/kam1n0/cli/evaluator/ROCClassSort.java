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
// Decompiled by Jad v1.5.8e. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.geocities.com/kpdus/jad.html
// Decompiler options: packimports(3) 
// Source File Name:   ClassSort.java

package ca.mcgill.sis.dmas.kam1n0.cli.evaluator;


public class ROCClassSort
    implements Comparable
{

    public ROCClassSort(double d, int i)
    {
        val = d;
        classification = i;
    }

    public int getClassification()
    {
        return classification;
    }

    public double getProb()
    {
        return val;
    }

    public int compareTo(Object obj)
    {
        double d = ((ROCClassSort)obj).getProb();
        if(val < d)
            return -1;
        if(val > d)
            return 1;
        int i = ((ROCClassSort)obj).getClassification();
        if(i == classification)
            return 0;
        return classification <= i ? 1 : -1;
    }

    private double val;
    private int classification;
}
