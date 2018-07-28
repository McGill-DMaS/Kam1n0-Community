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
package ca.mcgill.sis.dmas.kam1n0.vex;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.stream.IntStream;

import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.StmDirtyEffect;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.StmLoadGType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexConstantType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexJumpKind;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

public class VexEnumeration {

	private static org.slf4j.Logger logger = LoggerFactory.getLogger(VexEnumeration.class);

	public static class VexEnumerationConverter<T> {
		public HashMap<T, Integer> typeToIndex = new HashMap<>();
		public HashMap<Integer, T> indexToType = new HashMap<>();
	}

	private static HashMap<Class<?>, VexEnumerationConverter<?>> converters = new HashMap<>();

	public static <T extends Enum<T>> void register(T[] values, int startingValue, Class<?> enumType) {
		@SuppressWarnings("unchecked")
		VexEnumerationConverter<T> converter = (VexEnumerationConverter<T>) converters.getOrDefault(enumType,
				new VexEnumerationConverter<T>());
		IntStream.range(startingValue, startingValue + values.length).forEach(val -> {
			converter.indexToType.put(val, values[val - startingValue]);
			converter.typeToIndex.put(values[val - startingValue], val);
		});
		converters.put(enumType, converter);
	}

	public static <T extends Enum<T>> T retrieveType(int index, Class<?> enumType) {
		@SuppressWarnings("unchecked")
		VexEnumerationConverter<T> converter = (VexEnumerationConverter<T>) converters.get(enumType);
		if (converter == null) {
			logger.error("Getting null tpye: {} - {}", index, enumType.getName());
			return null;
		} else {
			T tp = converter.indexToType.get(index);
			// if (tp == null)
			// logger.error("Getting null tpye: {} - {}",
			// Integer.toHexString(index), enumType.getName());
			return tp;
		}
	}

	public static <T extends Enum<T>> Integer retrieveIndex(T type, Class<?> caller) {
		@SuppressWarnings("unchecked")
		VexEnumerationConverter<T> converter = (VexEnumerationConverter<T>) converters.get(caller);
		if (converter == null)
			return null;
		else
			return converter.typeToIndex.get(type);
	}

	public static void printRegisteredEnumerationConstructors(Class<?>... clses) {

		StringBuilder body = new StringBuilder();

		Arrays.stream(clses).forEach(cls -> {
			Method[] methods = cls.getMethods();
			for (int i = 0; i < methods.length; ++i) {
				if (methods[i].getName().equals("fromInteger")) {
					body.append("jobject create_enum_" + cls.getSimpleName().replace(".", "_")
							+ "(JNIEnv * jenv, jint index)").append(System.lineSeparator());
					body.append("{").append(System.lineSeparator());
					body.append("   jclass target_class = (*jenv)->FindClass(jenv, \"")
							.append(JniObject.getObjectClassTypeName(cls)).append("\");")
							.append(System.lineSeparator());
					body.append(
							"   jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv, target_class,  \"fromInteger\", \"(I)")
							.append(JniObject.getObjectClassTypeName(cls)).append("\");")
							.append(System.lineSeparator());
					body.append(
							"   return (*jenv)->CallStaticObjectMethod(jenv, target_class, java_static_method, index); ")
							.append(System.lineSeparator());
					body.append("}").append(System.lineSeparator());
				}
			}
		});

		System.out.println(body.toString());
	}

	public static void activate() {
		// register(StmDirtyEffect.values(), 0x1B00, StmDirtyEffect.class);
		// register(StmLoadGType.values(), 0x1D00, StmLoadGType.class);
		// register(VexConstantType.values(), 0x1300, VexConstantType.class);
		// register(VexEndnessType.values(), 0x1200, VexEndnessType.class);
		// register(VexExpressionType.values(), 0x1900,
		// VexExpressionType.class);
		// register(VexJumpKind.values(), 0x1A00, VexJumpKind.class);
		// register(VexOperationType.values(), 0x1400, VexOperationType.class);
		// register(VexStatementType.values(), 0x1E00, VexStatementType.class);
		// register(VexVariableType.values(), 0x1100, VexVariableType.class);

		register(StmDirtyEffect.values(), StmDirtyEffect.startValue(), StmDirtyEffect.class);
		register(StmLoadGType.values(), StmLoadGType.startValue(), StmLoadGType.class);
		register(VexConstantType.values(), VexConstantType.startValue(), VexConstantType.class);
		register(VexEndnessType.values(), VexEndnessType.startValue(), VexEndnessType.class);
		register(VexExpressionType.values(), VexExpressionType.startValue(), VexExpressionType.class);
		register(VexJumpKind.values(), VexJumpKind.startValue(), VexJumpKind.class);
		register(VexOperationType.values(), VexOperationType.startValue(), VexOperationType.class);
		register(VexStatementType.values(), VexStatementType.startValue(), VexStatementType.class);
		register(VexVariableType.values(), VexVariableType.startValue(), VexVariableType.class);
		register(VexArchitectureType.values(), VexArchitectureType.startValue(), VexArchitectureType.class);
	}

	public static void main(String[] args) {
		printRegisteredEnumerationConstructors(StmDirtyEffect.class, StmLoadGType.class, VexArchitectureType.class,
				VexConstantType.class, VexEndnessType.class, VexExpressionType.class, VexJumpKind.class,
				VexOperationType.class, VexStatementType.class, VexVariableType.class);
	}

}
