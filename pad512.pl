#!/usr/bin/perl

#
# (c) Dominic Beesley 2020
#
# MIT licence, see LICENCE.txt

# pad an image file for 512 byte sectors

use strict;

sub Usage(@) {
	my ($fh) = (@_);

	$fh = $fh // *STDERR;

	print $fh "

	pad512.pl <command> [options]<in file> <out file>

command = pad:
	Will pad each 256 byte sector to be 512 bytes in length, the padding will
	by default be every second byte = 0. Options below

command = condense:
	Padding bytes will be removed.

options:
	-even	(default) Every 2nd byte will be made to be zero
	-odd    The first of each 2 bytes will be made zero
	-start  The start of each sector will be all zero
	-end    The end of each sector will be all zero

	-force  Ignore non-zero padding bytes when condensing
";
}

#########################################################################################
# MAIN
#########################################################################################

use enum qw(:PAD_=0 EVEN ODD START END);

my $force = 0;
my $padtype = PAD_EVEN;

sub read_opts(@) {
	my @args = @_;

	while (@args[0] =~ /^-/) {		
		my $switch = shift @args;

		if ($switch eq "-even") {
			$padtype = PAD_EVEN;
		} elsif ($switch eq "-odd") {
			$padtype = PAD_ODD;
		} elsif ($switch eq "-start") {
			$padtype = PAD_START;
		} elsif ($switch eq "-end") {
			$padtype = PAD_END;
		} elsif ($switch eq "-force") {
			$force = 1;
		} else {
			die "Unrecognised switch \"$switch\"";
		}
	}

	return @args;
}

sub command_pad(@) {

	@_ = read_opts(@_);

	my $inname = shift or die "Missing input filename\n";
	my $outname = shift or die "Missing input filename\n";

	open (my $fh_in, "<:raw:", $inname) or die "Cannot open \"$inname\" for input : $!";
	open (my $fh_out, ">:raw:", $outname) or die "Cannot open \"$outname\" for output : $!";


	close $fh_in;
	close $fh_out;

}

sub checkz($@) {
	my ($ptr, @x) = @_;

	for my $i (0 .. $#x)
	{
		$x[$i] && die sprintf "Bad pad character %02X at %d (0x%x)", $x[$i], $ptr + $i, $ptr + $i;
	}

}


sub command_condense(@) {

	@_ = read_opts(@_);

	my $inname = shift or die "Missing input filename\n";
	my $outname = shift or die "Missing input filename\n";

	open (my $fh_in, "<:raw:", $inname) or die "Cannot open \"$inname\" for input : $!";
	open (my $fh_out, ">:raw:", $outname) or die "Cannot open \"$outname\" for output : $!";

	my $buf_in;

	my $ctr = 0;
	my $ptr = 0;
	while ((my $l = read($fh_in, $buf_in, 512)) > 0) {
		!$force && $l != 512 && die "Sector isn't 512 bytes long at $ptr ($l)";

		if ($l != 512) {
			$buf_in .= chr() x (512-$l);
		}

		my @arr_in = unpack("C*", $buf_in);


		if ($padtype == PAD_ODD || $padtype == PAD_EVEN) {
			my @odd;
			my @even;
			for (my $i = 0; $i < 512; $i+=2) 
			{
				push @odd, @arr_in[$i+0];
				push @even, @arr_in[$i+1];
			}

			if (!$force) {
				if ($padtype == PAD_ODD) {
					checkz($ptr, @odd);
				} else {
					checkz($ptr+1, @even);
				}
			}

			if ($padtype == PAD_ODD) {
				print $fh_out pack("C*", @even);
			} else {
				print $fh_out pack("C*", @odd);
			}
		}

		$ptr += $l;

		$ctr ++;

		if (($ctr % 256) == 0) {
			print ".";
			select()->flush();
		}
	}

	close $fh_in;
	close $fh_out;

}

my $command = shift or die "Missing command";

if ($command eq "help" || $command eq "--help") {
	Usage(*STDIN);
} elsif ($command eq "pad") {
	command_pad(@ARGV);
} elsif ($command eq "condense") {
	command_condense(@ARGV);
} else {
	Usage();
	die "Unrecognised command \"$command\"";
}

