#
# (c) Dominic Beesley 2020
#
# MIT licence, see LICENCE.txt

#!/usr/bin/perl

# A simple ADF imager

use strict;
use File::Basename qw( fileparse );
use File::Path qw( make_path );
use File::Spec;

my	$BADSPECCHARS = "\$%&@:^.";
my	$FLAGNAMES = "RWLDErwepx";


use constant {

	FLAG_R => 0x001,
	FLAG_W => 0x002,
	FLAG_L => 0x004,
	FLAG_D => 0x008,
	FLAG_E => 0x010,
	FLAG_r => 0x020,
	FLAG_w => 0x040,
	FLAG_e => 0x080,
	FLAG_p => 0x100


};

my	$ROOTDIRENT = {
	rawname => "\$",
	name => "\$",
	flags => FLAG_D | FLAG_L | FLAG_R,
	load => 0x00000000,
	exec => 0x00000000,
	length => 0x00000500,
	sector => 0x000002,
	seq => 0
};


sub read32bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 4) != 4) {
		return 0;
	}
	else
	{
		$_[1] = unpack("L", $buf);
		return 1;
	}

}


sub read24bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 3) != 3) {
		return 0;
	}
	else
	{
		my @n = unpack("CCC", $buf);
		$_[1] = @n[0] + (@n[1] << 8) + (@n[2] << 16);
		return 1;
	}

}

sub read16bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 2) != 2) {
		return 0;
	}
	else
	{
		my @n = unpack("CC", $buf);
		$_[1] = @n[0] + (@n[1] << 8);
		return 1;
	}

}


sub read8bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 1) != 1) {
		return 0;
	}
	else
	{
		my @n = unpack("C", $buf);
		$_[1] = @n[0];
		return 1;
	}

}


sub readbytes($$$) {
	my $fh = $_[0];
	my $len = $_[1];
	my $buf;

	if (read($fh, $buf, $len) != $len) {
		return 0;
	}
	else
	{
		$_[2] = $buf;
		return 1;
	}

}

sub ckadd($$) {
	my $ret = $_[0];
	if ($ret > 255) {
		$ret = ($ret + 1) & 0xFF;
	}
	$ret += $_[1] & 0xFF;
	$_[0] = $ret;
}

sub ckadd24($$) {

	ckadd($_[0], $_[1] >> 16);
	ckadd($_[0], $_[1] >> 8);
	ckadd($_[0], $_[1]);	
}

sub ckadd16($$) {

	ckadd($_[0], $_[1] >> 8);
	ckadd($_[0], $_[1]);	
}

#speak to JGH about this - not quite right in doco?
sub ckaddstr($$) {

	my @str = unpack("C*", $_[1]);
	for (my $i = scalar(@str)-1; $i >= 0; $i--) {
		ckadd($_[0], @str[$i]);	
	}

}


sub makesec0cksum($) {
	my ($disk) = @_;

	my $ret = 0;

	ckadd24($ret, $disk->{disksize});
	ckaddstr($ret, $disk->{ronameeven});
	ckadd24($ret, $disk->{l3sec1});

	for (my $i = 81; $i >= 0; $i--) {
		ckadd24($ret, $disk->{fsmap}->{starts}->[$i]);
	}


	return $ret & 0xFF;
}

sub makesec1cksum($) {
	my ($disk) = @_;

	my $ret = 0;

	ckadd($ret, $disk->{fsmap}->{len3});
	ckadd($ret, $disk->{opt4});
	ckadd16($ret, $disk->{diskid});
	ckaddstr($ret, $disk->{ronameodd});


	for (my $i = 81; $i >= 0; $i--) {
		ckadd24($ret, $disk->{fsmap}->{lengths}->[$i]);
	}


	return $ret & 0xFF;
}


sub readimage($) {
	my ($fn) = @_;

	my %ret = ();

	open(my $fh, "<:raw:", $fn) or die "Cannot open $fn: $!";


	#############################################################
	# sector 0
	#############################################################
	# 82 free space pointers
	my @free_starts = ();
	for (my $i = 0; $i < 82; $i++) {
		read24bit($fh, my $fs) or die "EOF reading sector 0";
		push @free_starts, $fs
	}
	$ret{fsmap}->{starts} = \@free_starts;

	read24bit($fh, $ret{l3sec1}) or die "EOF reading sector 0";
	readbytes($fh, 3, $ret{ronameeven}) or die "EOF reading sector 0";
	read24bit($fh, $ret{disksize}) or die "EOF reading sector 0";
	read8bit($fh, my $ck0) or die "EOF reading sector 0";

	my $ckc0 = makesec0cksum(\%ret);

	$ckc0 == $ck0 or die "Bad checksum sector 0 $ck0 |= $ckc0";

	$ret{disksize} >= 10 or die "Bad disk size!";

	#############################################################
	# sector 1
	#############################################################
	# 82 free space pointers
	my @free_lengths = ();
	for (my $i = 0; $i < 82; $i++) {
		read24bit($fh, my $fs) or die "EOF reading sector 0";
		push @free_lengths, $fs
	}
	$ret{fsmap}->{lengths} = \@free_lengths;

	read24bit($fh, $ret{l3sec2}) or die "EOF reading sector 0";
	readbytes($fh, 2, $ret{ronameodd}) or die "EOF reading sector 0";
	read16bit($fh, $ret{diskid}) or die "EOF reading sector 0";
	read8bit($fh, $ret{opt4}) or die "EOF reading sector 0";
	read8bit($fh, $ret{fsmap}->{len3}) or die "EOF reading sector 0";
	read8bit($fh, my $ck1) or die "EOF reading sector 0";

	my $ckc1 = makesec1cksum(\%ret);

	$ckc1 == $ck1 or die "Bad checksum sector 0 $ck1 |= $ckc1";

	#read rest of disk as Data
	my $ds = 256 * ($ret{disksize}-2);
	my $dat;
	my $l = read($fh, $dat, $ds);

	if ($l < $ds) {
		$dat .= "\0" x ($ds-$l);
	}

	# this is pants!
	my $interleave = ($ret{disksize} = 0xA00)?16:0;
	$ret{interleave} = $interleave;


	#de-interleave the data if necessary
	if ($interleave) {
		my ($dat_a, $dat_b, $ptr, $n);
		$dat = ("\0" x 0x200) . $dat;

		length($dat) % ($interleave * 256 * 2) == 0 or die "Bad interleave";

		$n = int(length($dat) / ($interleave * 256 * 2));

		for (my $i = 0; $i < $n; $i++) {
			$dat_a .= substr($dat, $ptr, $interleave * 256);
			$ptr+=$interleave * 256;
			$dat_b .= substr($dat, $ptr, $interleave * 256);
			$ptr+=$interleave * 256;
		}

		$dat = substr($dat_a . $dat_b, 0x200);
	}

	$ret{data} = $dat;

	close($fh);

	return \%ret;
}

sub debuginfo($) {
	my ($disk) = @_;

	print "FREESPACEMAP[\n";
	for (my $i = 0; $i < int($disk->{fsmap}->{len3} / 3); $i++) {
		my $s = $disk->{fsmap}->{starts}->[$i];
		my $l = $disk->{fsmap}->{lengths}->[$i];
		printf("%4d : %06X+%06X=%06X\n", $i, $s, $l, $s+$l);
	}
	print "]\n";
	printf "DISKSIZE=%06X %dK\n", $disk->{disksize}, ($disk->{disksize}*256)/1024;
	printf "OPT4=%1X\n", $disk->{opt4};

}

sub readdirent($) {
	my $fh = $_[0];
	my %ret = ();
	my $flags = 0;
	my $name = "";
	readbytes($fh, 10, my $nameandflags) or die "Error reading directory entry";
	$ret{rawname} = $nameandflags;
	#decipher name and flags
	my $l = -1;
	for (my $i = 0; $i <= 9; $i++) {
		my $c = ord(substr($nameandflags, $i, 1));
		$name .= chr($c & 0x7F);
		$flags = $flags >> 1;
		$flags = $flags | (($c & 0x80)?0x200:0);
		$c = $c & 0x7F;
		if ($l == -1 && ($c == 0x0d || $c == 0x00))
		{
			$l = $i;
		}
	}
	if ($l >= 0)
	{
		$name = substr($name, 0 , $l);
	}
	$ret{name} = $name;
	$ret{flags} = $flags;
	read32bit($fh, $ret{load}) or die "Error reading directory entry";
	read32bit($fh, $ret{exec}) or die "Error reading directory entry";
	read32bit($fh, $ret{length}) or die "Error reading directory entry";
	read24bit($fh, $ret{sector}) or die "Error reading directory entry";
	read8bit($fh, $ret{seq}) or die "Error reading directory entry";

	return \%ret;
}

sub safestr($) {
	my ($str) =@_;
	for (my $i = 0; $i < length($str); $i++) {
		my $c = substr($str, $i, 1);
		if (ord($c) < 32 || ord($c) > 127) {
			printf "\\x%02X", ord($c);
		}
		else {
			print $c;
		}
	}
}

sub notopbit($) {
	my $str = $_[0];
	my $ret = "";
	for my $i (0..length($str)) {
		my $c = ord(substr($str, $i, 1));
		$ret .= chr($c & 0x7F);
	}
	return $ret;
}

sub unpackdir($$) {
	my ($disk, $sector) = @_;

	$sector >= 2 || $sector <= $disk->{disksize} - 5 or die "Directory index out of bounds [$sector]";

	my $dirdata = substr($disk->{data}, 256*($sector-2), 5*256);

	#open the directory data as a file
	open(my $fh, "<:raw:", \$dirdata) or die "Cannot read directory as string [$sector]";

	my %ret = ();
	read8bit($fh, $ret{seq}) or die "Error reading directory [$sector] 1";
	readbytes($fh, 4, my $hugo1) or die "Error reading directory [$sector] 2";

	$hugo1 eq "Hugo" or die "Not Hugo! (0) : " . safestr($hugo1) . "[$sector]";

	my @dirents = ();
	my $n = 47;
	for (my $i = 0; $i < 47; $i++) {
		my $dirent = readdirent($fh);
		push @dirents, $dirent;		

		if ($n > $i && !length($dirent->{name}))
		{
			$n = $i;
		}
	}

	$ret{entries} = \@dirents;
	$ret{length} = $n;


	my $x;
	read8bit($fh, $x) or die "Error reading directory [$sector] 3";
	$x == 0 or die "Unexpected value $x at offset 4CB in directory [$sector] 4";
	readbytes($fh, 10, $ret{rawname}) or die "Error reading directory [$sector] 5";
	read24bit($fh, $ret{parent}) or die "Error reading directory [$sector] 6";
	readbytes($fh, 19, $ret{rawtitle}) or die "Error reading directory [$sector] 7";
	readbytes($fh, 14, $x) or die "Error reading directory [$sector] 8";
	$x eq "\0" x 14 or die "Unexpected stuff in resereved 4EC [$sector] 9";

	read8bit($fh, my $seq2) or die "Error reading directory";
	readbytes($fh, 4, my $hugo2) or die "Error reading directory [$sector] 10";

	$hugo2 eq "Hugo" or die "Not Hugo! (2) : " . safestr($hugo2) . " [$sector] 11";
	$seq2 == $ret{seq} or die "Mismatched sequence numbers $seq2 != $ret{seq} [$sector] 12";

	$ret{name} = notopbit($ret{rawname});
	$ret{name} =~ s/[\r\n\0].*//;
	$ret{title} = notopbit($ret{title});
	$ret{title} =~ s/[\r\n\0].*//;

	#ignore checksum for now!
	read8bit($fh, my $ck) or die "Error reading directory [$sector] 13";

	close $fh;

	return \%ret;
}

sub flags2str($) {
	my ($flags) = @_;
	my $ret;
	for (my $i = 9; $i >=0; $i--)
	{
		$ret .= ($flags & (1 << $i))?substr($FLAGNAMES, $i, 1):"-";

	}
	return $ret;
}

sub debuginfodir($) {
	my ($dir) = @_;

	printf "DIR: %10s [%19s]\n", $dir->{name}, $dir->{title};

	for (my $i = 0; $i < $dir->{length}; $i++) {
		
		printf "  %3X %10s %08X %08X %08X %06X %s\n"
			, $dir->{entries}->[$i]->{flags}
			, flags2str($dir->{entries}->[$i]->{flags})
			, $dir->{entries}->[$i]->{load}
			, $dir->{entries}->[$i]->{exec}
			, $dir->{entries}->[$i]->{length}
			, $dir->{entries}->[$i]->{sector}
			, $dir->{entries}->[$i]->{name};
	}
}


sub treedump($$$) {
	my ($disk, $dir, $parname) = @_;

	my $prefix = "$parname.$dir->{name}";
	for my $ent (dirents($dir)) {
		if ($ent->{flags} & FLAG_D) {
			printf "====%06X%====\n", $ent->{sector};
			treedump($disk, unpackdir($disk, $ent->{sector}), $prefix);
		} else {
			print "$prefix.$ent->{name}\n";
		}
	}


}


#munge a adfs file spec (with wildcards) to a regex matching string
sub spec2re($) {
	my ($spec) = @_;

	my $ret = "";

	for my $c (split(//, $spec)) {
		if ($c =~ /[\Q$BADSPECCHARS\E]/) {
			return "";
		} elsif ($c eq "#") {
			$ret .= ".";
		} elsif ($c eq "*") {
			$ret .= ".*?";
		} elsif ($c eq ".") {
			$ret .= "\\.";
		} else {
			$ret .= "\Q$c\E";
		}

	}

	$ret =~ s/\\\.\\%\\\./(\.[^.]+)+\./;

	$ret = "$ret";

	return $ret;
}


sub spec2repath($) {
	my ($spec) = @_;
	my $ret = "";

	$spec =~ s/^\$\.//;

	for my $s (split(/\./, $spec)) {
		if ($s eq "")
		{
			$ret .= "\\.";
		} elsif ($s eq "%") {
			$ret .= "(\\.[^.]+)+";
		} else {
			$ret .= spec2re($s);
		}
	}

	$ret .= "\\.";

	return "^\\\$\\.$ret";
}

##return valid directory entries from a directory as an array
sub dirents($) {
	my ($dir) = @_;
	return @{$dir->{entries}}[0 .. $dir->{length}-1];
}

#returns true false if any matched and 3rd argument is out
#array of direntsmatches i.e. {path =>, dirent =>}
#the path is the path to the directory containing the dirent
#returns -1 if a bad filespec is encountered, 0 if no matches
#!=0 for matches
sub finddirents($$$) {
	my ($disk, $spec) = @_;
	my $dir = unpackdir($disk, 0x2);

	return finddirents_int($disk, $dir, $spec, "\$.", $_[2]);
}

sub finddirents_int($$$$$) {
	my ($disk, $dir, $spec, $parpath) = @_;


	my @specs = split(/\./, $spec);
	my $spechere = @specs[0];
	my $specrest = join('.', splice(@specs, 1));

	my $ret = 0;

	if ($spechere eq "")
	{
		return -1; #.. found
	}

	if ($spechere eq "\$") {
		if ($specrest ne "") {
			return finddirents_int($disk, unpackdir($disk, 0x2), $specrest, "\$.", $_[4]);
		} else {
			$_[4] = [{ path => "", dirent => $ROOTDIRENT } ];
			return 1
		}
	}
	elsif ($spechere eq "^")
	{
		if ($dir->{name} eq "\$") {
			#ADFS doesn't seem to do this - instead returns "Broken directory"
			return finddirents_int($disk, unpackdir($disk, 0x2), $specrest, "\$.", $_[4]);
		} else {			
			my $pd = $parpath;
			$pd =~ s/^(.*?)\.[^\.]+$/\1/;
			return finddirents_int($disk, unpackdir($disk, $dir->{parent}), $specrest, "$pd.", $_[4]);
		}
	} 
	elsif ($spechere eq "%")
	{
		if ($specrest)
		{
			my $r = finddirents_int($disk, $dir, $specrest, "$parpath", $_[4]);
			if ($r < 0) {
				return $r;
			} else {
				$ret += $r;
			}
		}
		for my $d (dirents($dir)) {
			if ($d->{flags} & FLAG_D) {
				if ($specrest) {
					my $r = finddirents_int($disk, unpackdir($disk, $d->{sector}), $spec, "$parpath$d->{name}.", $_[4]);
					if ($r < 0) {
						return $r;
					} else {
						$ret += $r;
					}
				} else {
					push @{$_[4]}, {path => $parpath, dirent => $d};
				}
			}
		}

	}
	elsif ($specrest) {
		# non-leaf - look for directories

		my $specherere = "^" . spec2re($spechere) . "\$";

		for my $d (dirents($dir)) {
			if (($d->{name} =~ /$specherere/i) && ($d->{flags} & FLAG_D)) {
				my $r = finddirents_int($disk, unpackdir($disk, $d->{sector}), $specrest, "$parpath$d->{name}.", $_[4]);		
				if ($r < 0) {
					return $r;
				} else {
					$ret += $r;
				}
			}
		}
	} else {
		# leaf match any objects

		my $specherere = spec2re($spechere);

		for my $d (dirents($dir)) {
			if ($d->{name} =~ /$specherere/i) {
				push @{$_[4]}, {path => $parpath, dirent => $d};
			}
		}
	}

}


sub Usage() {
	print STDERR "

	adf <command> [option...] <imagename> [<filespec>...]

command = info:
	Displays a listing of directory contents, <filespec> contains a file
	and directory spec to match. If there are multiple filespecs then
	all files and directories matching will be returned

	Options:
		-n|--names - will only display file names instead of full info
		-f|--files - will only display matching files (not directories)

	EXAMPLES:
	
	\$ adf info cf11.adf %.ROMS.ADFS*

	Will search the entire disk for any directory \"ROMS\" and return any files
	within that directory (or any contained directory) for files starting \"ADFS\"

	\$ adf info dom.adl %.*/adl

	Will search the entire disk for any files ending \"/adl\"

	\$ adf info dom.adl %.*/adl %.*/adf

	Will search the entire disk for any files ending \"/adl\" or \"/adf\"

	\$ adf info dom.adl $.src.%.h.*

	Will search the entire src directory tree for any files in directories
	named \"h\" at whatever level.

command = read:
	-d|--dest followed by a directory name. This switch is mandatory the 
		directory must exist it must be empty
	-x|--excludedirs the given directory prefix will be removed before
		any directories in the output. The special prefix % indicates
		find the smallest common root.
	-f|--flatten don't create directories in the output, files with a 
		similar name will be given a .NNN suffix

	By default the full directory tree from the root of the image will
	be recreated in the destiation directory. i.e. if the following 
	files are matched:

	$.DATA.ROMS.Acorn.WORDW
	$.DATA.ROMS.Dom.Willy
	$.DATA.PROGS.Bob.Worms

	were matched and the destination directory is ./dump the following
	file will be created:

	./dump/DATA/ROMS/Acorn/WORDW
	./dump/DATA/ROMS/Dom/Willy
	./dump/DATA/PROGS/Bob/Worms

	if -x $.DATA.ROMS is specified then:

	./dump/Acorn/WORDW
	./dump/Dom/Willy
	./dump/DATA/PROGS/Bob/Worms

	if -x $.DATA.ROMS -x $.DATA.PROGS is specified then:

	./dump/Acorn/WORDW
	./dump/Dom/Willy
	./dump/Bob/Worms

	if -x @ then:

	./dump/ROMS/Acorn/WORDW
	./dump/ROMS/Dom/Willy
	./dump/PROGS/Bob/Worms

Note: be careful about wildcards and whatever environment you are running in you
may need to quote the strings with wildcards and $ signs depending on if you're 
running in a *nix or DOS environment. i.e. in bash:

$ ./adf.pl info x.adf * 

would expand to have the names of files in the current directory in place of the *

$ /adf.pl info x.adf '*'

would be better

";
}

sub command_info(@) {

	my @args = @_;
	my $sw_names = 0;
	my $sw_files = 0;

	while (@args[0] =~ /^-/) {
		my $switch = shift @args;

		if ($switch eq "-n" || $switch eq "--names")
		{
			$sw_names = 1;
		} elsif ($switch eq "-f" || $switch eq "--files")
		{
			$sw_files = 1;
		} else {		
			die "Unrecognised switch \"$switch\"";
		}
	}

	my $imagename = shift @args or die "Missing image filename";

	my $disk = readimage($imagename);

	my %all = ();

	my @specs = @args;

	if (!scalar @specs) {
		push @specs, "$.*";
	}

	while (my $filespec = shift @specs) {

		my $dps;
		my $c = finddirents($disk, $filespec, $dps);
		$c < 0 and die "Bad filespec $filespec";		

		for my $dp (@{$dps}) {
			my $fullname = "$dp->{path}$dp->{dirent}->{name}";
			$all{$fullname} = $dp;
		}
	}

	my $lastp = "";
	for my $k (sort keys %all) {
		my $dp = $all{$k};

		if ($sw_files == 0 || !($dp->{dirent}->{flags} & FLAG_D)) {
			if ($sw_names) {
				print "$dp->{path}$dp->{dirent}->{name}\n";
			} else {
				if ($lastp eq "" || $lastp ne $dp->{path}) {
					print "[$dp->{path}]\n";
					$lastp = $dp->{path};
				}
				printf "%-10s %9s (%2d)  %08X  %08X  %08X  %06X\n"
					, $dp->{dirent}->{name}
					, flags2str($dp->{dirent}->{flags})
					, $dp->{dirent}->{seq}
					, $dp->{dirent}->{load}
					, $dp->{dirent}->{exec}
					, $dp->{dirent}->{length}
					, $dp->{dirent}->{sector};			
			}
		}


	}

}

sub is_folder_empty($) { 
	my $dirname = shift; 
	opendir(my $dh, $dirname) or die "Not a directory"; 
	return scalar(grep { $_ ne "." && $_ ne ".." } readdir($dh)) == 0; 
}

sub command_read(@) {

	my @args = @_;
	my $destdir = "";
	my @excludedirs = ();
	my $excludecommon = 0;
	my $flatten = 0;

	while (@args[0] =~ /^-/) {
		my $switch = shift @args;

		if ($switch eq "-d" || $switch eq "--dest") {
			$destdir = shift @args or die "Missing destination directory name";
		} elsif ($switch eq "-x" || $switch eq "--excludedirs") {
			my $e = shift @args or die "Missing excludedirs";
			if ($e eq "@") {
				$excludecommon = 1;
			} else {
				push @excludedirs, $e;
			}
		} elsif ($switch eq "-f" || $switch eq "--flatten") {
			$flatten = 1;
		} else {
			die "Unrecognised switch \"$switch\"";
		}
	}

	$destdir or die "You must specify a destination directory";
	
	if (! -d $destdir) {
		die "$destdir doesn't exist";
	}
	if (!is_folder_empty($destdir)) {
		die "$destdir isn't empty";
	}

	my $imagename = shift @args or die "Missing image filename";

	my $disk = readimage($imagename);

	my %all = ();

	while (my $filespec = shift @args) {


		my $dps;
		my $c = finddirents($disk, $filespec, $dps);
		$c < 0 and die "Bad filespec \"$filespec\"";		

		for my $dp (@{$dps}) {
			my $fullname = "$dp->{path}$dp->{dirent}->{name}";
			$all{$fullname} = $dp;
		}
	}

	my $commonroot = "";
	for my $k (sort keys %all) {
		my $p = $all{$k}->{path};
		if ($commonroot eq "") {
			$commonroot = $k;
		} elsif (!($p =~ /^\Q$commonroot\E.*/i)) {
			my $l = 1;
			while (
				$l < length($commonroot) && 
				$l < length($p) && 
				uc substr($commonroot, 0, $l) eq uc substr($p, 0, $l)
				) {
				$l++;
			}
			$commonroot = substr($commonroot, 0, $l - 1);
		}
	}

	$commonroot =~ s/^(([^.]+\.)+)[^.]+$/\1/; #remove partial directory names


	my $lastp = "";
	for my $k (sort keys %all) {
		my $dp = $all{$k};

		if (!($dp->{dirent}->{flags} & FLAG_D)) {

			my $path = $dp->{path};

			my $rest;

			if ($flatten) {
				$rest = "";
			} else {
				$rest = $path;

				for my $e (@excludedirs) {
					my $rest2;
					if (matchpath($path, $e, $rest2)) {
						if (length($rest) > length($rest2))
						{
							$rest = $rest2;
						}
					}

				}

				if ($excludecommon && length($rest) > length($path) - length($commonroot)) {
					$rest = substr($path, length($commonroot));
				}

				$rest =~ s/^\$\.//;
			}

			$rest = safeDOSUnixPath($rest);

			my $dir = File::Spec->catdir($destdir, $rest);

			if (!-d $dir) {
				make_path($dir);
			}

			my $safefn = safeDOSUnixFilename($dp->{dirent}->{name});
			my $fn = File::Spec->catfile($dir, $safefn);
			my $ctr = 0;
			my $suf = "";
			while (-e "$fn$suf") {
				$ctr++;
				$suf = sprintf(".%03d", $ctr);
				$ctr >= 1000 and die "Cannot create a unique name;"
			}

			$fn = "$fn$suf";


			open (my $fho, ">:raw:", $fn) or die "Cannot open $fn for output $!";

			my $len = $dp->{dirent}->{length};
			my $st = ($dp->{dirent}->{sector} - 2) * 256;

			print $fho substr($disk->{data}, $st, $len);

			close $fho;

			# make .inf filespec

			open (my $fhi, ">", "$fn.inf") or die "Cannot open $fn.inf for output $!";

			printf $fhi "%-10s %08X %08X %08X %02X\n"
				, $dp->{dirent}->{name}
				, $dp->{dirent}->{load}
				, $dp->{dirent}->{exec}
				, $dp->{dirent}->{length}
				, $dp->{dirent}->{flags}
				;

			close $fhi;

		}


	}


	print "COMMONROOT: $commonroot\n";

}


sub matchpath($$$) {
	my ($path, $spec) = @_;

	my $spec_re = spec2repath($spec);	

	my $ret = $path =~ /($spec_re)(.*)$/i;
	if ($ret)
	{
		my $s = $1;
		my $r = $2;
		$_[2] = $r;
	}
	return $ret;
}


sub safeDOSUnixFilename($) {
	my ($l) = @_;

	$l =~ tr/\?<>\/\\/#$^.@/;	#differs from JGH - \\ => @
	return $l;
}


sub safeDOSUnixPath($) {
	my ($l) = @_;
	my $ret = "";

	for my $s (split(/\./, $l)) {
		if ($ret ne "") {
			$ret = File::Spec->catdir($ret, safeDOSUnixFilename($s));
		} else {
			$ret = safeDOSUnixFilename($s);
		}
	}
	return $ret;
}


#########################################################################################
# MAIN
#########################################################################################

my $command = shift or die "Missing command";

if ($command eq "info") {
	command_info(@ARGV);
} elsif ($command eq "read") {
	command_read(@ARGV);
} else {
	die "Unrecognised command \"$command\"";
}


#
#my $disk = readimage("test-images/cf11.dat");
#
#debuginfo($disk);
#
#my $rootdir = unpackdir($disk, 0x2);
#
#debuginfodir($rootdir);
#
##treedump($disk, $rootdir, "");
#
#my $spec = "ROMS.*.Apps.*wwis*";
#my $dps;
#my $c = finddirents($disk, $spec, $dps);
#$c < 0 and die "Bad filespec $spec";
#for my $d (@$dps) {
#	printf "[%s.]%s\n", $d->{path}, $d->{dirent}->{name};
#}