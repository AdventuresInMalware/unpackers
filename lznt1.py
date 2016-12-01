#!/usr/bin/env python
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## Copyright (C) 2016 Airbus Defence and Space Cybersecurity               ##
## This document is the property of Airbus Defence and Space Cybersecurity ##
##                                                                         ##
##                                                                         ##
## Licensed under the Apache License, Version 2.0 (the "License");         ##
## you may not use this file except in compliance with the License.        ##
## You may obtain a copy of the License at                                 ##
##                                                                         ##
##     http://www.apache.org/licenses/LICENSE-2.0                          ##
##                                                                         ##
## Unless required by applicable law or agreed to in writing, software     ##
## distributed under the License is distributed on an "AS IS" BASIS,       ##
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.##
## See the License for the specific language governing permissions and     ##
## limitations under the License.                                          ##
##                                                                         ##
##  Author: Andy Dove <andrew.dove@airbus.com                              ##
##                                                                         ##
#############################################################################

import struct

# This code is adapted from a C# implementation (c) 2008-2011, Kenneth Bell
# https://searchcode.com/codesearch/view/2392831.
# Only the decompression routine has been converted.
#
# See https://msdn.microsoft.com/library/hh554002.aspx for a full description of
# the LZNT1 algorithm.

def CalcCompressionBits(size):
	result = bytearray(size)
	offsetBits = 0
	y = 0x10
	for x in range(size):
		result[x] = 4 + offsetBits
		if(x == y):
			y = y << 1
			offsetBits += 1
			
	return result 

def decompress(source,sourceLength,sourceOffset, decompressed, decompressedLength, decompressedOffset):
	SubBlockIsCompressedFlag = 0x800
	SubBlockSizeMask = 0x0fff
	FixedBlockSize = 0x1000
	s_compressionBits = CalcCompressionBits(4096)

	sourceIdx = 0
	destIdx = 0

	source = bytearray(source)

	while(sourceIdx < sourceLength):
		header = struct.unpack('<H',str(source[(sourceIdx + sourceOffset):(sourceIdx + sourceOffset + 2)]))[0]
		sourceIdx += 2
		
		# Look for null-terminating sub-block header
		if(header == 0):
			break
			
		if( (header & SubBlockIsCompressedFlag) == 0):	# Current Chunk is uncompressed	
			blockSize = (header & SubBlockSizeMask) + 1
			decompressed[destIdx:destIdx + blockSize] = source[sourceIdx:sourceIdx + blockSize]
			sourceIdx += blockSize
			destIdx += blockSize
			
		else:
			destSubBlockStart = destIdx
			srcSubBlockEnd = sourceIdx + (header & SubBlockSizeMask) + 1

			while (sourceIdx < srcSubBlockEnd):
				tag = source[sourceOffset + sourceIdx]
				sourceIdx += 1
				
				for token in range(8):
					
					# Abort if we hit the end of the sub-block while still working through a tag
					if(sourceIdx >= srcSubBlockEnd):
						print "Sub-Block Ended Abruptly"
						break
						
					if((tag & 1) == 0): # Current sub-chunk is uncompressed
						if(decompressedOffset + destIdx >= len(decompressed)):
							return destIdx
							
						decompressed[decompressedOffset + destIdx] = source[sourceOffset + sourceIdx]
						destIdx += 1
						sourceIdx += 1
					else: # Sub-chunk is compressed
						lengthBits = 16 - s_compressionBits[destIdx - destSubBlockStart]
						lengthMask = (1 << lengthBits) - 1
						
						phraseToken = struct.unpack('<H',source[(sourceIdx + sourceOffset):(sourceIdx + sourceOffset + 2)])[0]
						sourceIdx += 2
						
						destBackAddr = destIdx - (phraseToken >> lengthBits) - 1
						length = (phraseToken & lengthMask) + 3
						
						for i in range(length):
							decompressed[decompressedOffset + destIdx] = decompressed[decompressedOffset + destBackAddr]
							destIdx += 1
							destBackAddr += 1
					tag >>= 1
			
			if (decompressedOffset + destIdx + FixedBlockSize > len(decompressed)):
				return destIdx
			elif (destIdx < destSubBlockStart + FixedBlockSize):
				skip = (destSubBlockStart + FixedBlockSize) - destIdx
				destIdx += skip;
