#!/usr/bin/python3
#
#	TwoColPrint - Print text in two columns, wrap as appropriate.
#	Copyright (C) 2011-2012 Johannes Bauer
#	
#	This file is part of jpycommon.
#
#	jpycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	jpycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with jpycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID c2de9b77-c699-490d-930f-21689e04b12f

import sys
import textwrap
import collections

_Row = collections.namedtuple("Row", [ "left", "right", "annotation" ])

class TwoColPrint(object):
	def __init__(self, prefix = "", total_width = 120, spacer_width = 3, width_ratio = 0.25):
		self._rows = [ ]
		self._prefix = prefix
		self._total_width = total_width
		self._spacer_width = spacer_width
		self._width_ratio = width_ratio
	
	def addrow(self, left_col, right_col, annotation = None):
		self._rows.append(_Row(left = left_col, right = right_col, annotation = annotation))
		return self

	def __iter__(self):
		text_width = self._total_width - len(self._prefix) - self._spacer_width
		assert(text_width > 2)
		left_width = round(self._width_ratio * text_width)
		right_width = text_width - left_width
		assert(len(self._prefix) + left_width + self._spacer_width + right_width == self._total_width)
		
		spacer = " " * self._spacer_width
		for row in self._rows:
			left_break = textwrap.wrap(row.left, width = left_width)
			right_break = textwrap.wrap(row.right, width = right_width)

			if len(left_break) < len(right_break):
				left_break += [ "" ] * (len(right_break) - len(left_break))
			elif len(left_break) > len(right_break):
				right_break += [ "" ] * (len(left_break) - len(right_break))

			for (leftline, rightline) in zip(left_break, right_break):

				yield ("%s%-*s%s%s" % (self._prefix, left_width, leftline, spacer, rightline), row.annotation)

	def print(self, f = None):
		if f is None:
			f = sys.stdout
		for (line, annotation) in self:
			print(line, file = f)

if __name__ == "__main__":
	t = TwoColPrint(prefix = "    ")
	t.addrow("foobar", "This is the first piece, which is foobar. A foobar is very cool! This is the first piece, which is foobar. A foobar is very cool!")
	t.addrow("barfjdiojf", "And here's a barwhatever And here's a barwhatever And here's a barwhatever")
	t.addrow("x", "Cool, a x.")
	t.addrow("And here's a barwhatever And here's a barwhatever And here's a barwhatever", "barfjdiojf")
	t.print()



