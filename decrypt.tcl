#!/cygdrive/c/tcl/bin/tclsh
package require aes;
set verbose 0;

proc my_puts {instring} {
    if {$::verbose} {
	puts $instring;
    } else {
	;
    }
}

proc to_hex {ascii} {
    scan $ascii %c hex;
    return $hex;
}

set fin [lindex $argv 0];
set key_data_ascii [lindex $argv 1];


if {[file exists $fin]} {
    puts "Decrypting file <$fin>";
} else {
    puts "File <$fin> Does Not Exist";
    exit;
}

if {$argc != 3} {
    puts "arguments are <filename> <key> <keep_decrypted_file>,  please try again."
    exit;
}

set fout $fin.d;

set p_fin [open $fin r];

if {[lindex $argv 2]=="keep_it"} {
    set p_fout [open $fout w];
    fconfigure $p_fout -translation binary;
} else {
    set p_fout stdout;
}

fconfigure $p_fin -translation binary;

set pt_binary [read $p_fin];
close $p_fin;

binary scan $pt_binary H* pt_hex;
#puts $pt_hex;

set pt_hex_list [split $pt_hex {}];
set pt_num_nibbles [llength $pt_hex_list];
set pt_num_blocks [expr int(ceil($pt_num_nibbles/32.0))];

#my_puts $pt_hex_list;
my_puts $pt_num_blocks;

#break into blocks
for {set j 0} {$j < $pt_num_blocks} {incr j} {
    set pt_block($j) {};
    for {set i 0} {$i < 32} {incr i} {
	if {($j * 32 + $i) < $pt_num_nibbles} {
#	    set pt_block($j) [join "$pt_block($j) [lindex $pt_list_ascii [expr $j * 16 + $i]]" {}];
	    lappend pt_block_hex($j) [lindex $pt_hex_list [expr $j * 32 + $i]];
#	    puts ||$pt_block($j)||;
	}
    }
    set pt_block_hex($j) [join $pt_block_hex($j) {}];
#    my_puts ||$pt_block_hex($j)||;
}

#pad key if not long enough or truncate if too long
set key_ascii_list [split $key_data_ascii {}];
set key_length [expr [llength $key_ascii_list]];
for {set i 0} {$i < (16 - $key_length)} {incr i} {
    lappend key_ascii_list f;
}

#my_puts $key_ascii_list;

set key_data_hex {};
for {set i 0} {$i < 16} {incr i} {
    lappend key_data_hex [format %02x [to_hex [lindex $key_ascii_list $i]]];
}
set key_data_hex [join $key_data_hex {}];
#my_puts $key_data_hex;

set key_data [binary format H* $key_data_hex];

#set iv {};
#set iv_ctr 0;
#for {set i 4} {$i < 16} {incr i} {
#    lappend iv [format %02x [expr int(rand() * 0x100)]];
#    #lappend iv [format %02x 1];
#}

#my_puts [format %016x 0];
set key [aes::Init ecb $key_data [format %016x 0]];

#set iv [join "$iv [format %08x $iv_ctr]" {}];
set iv $pt_block_hex(0);
#my_puts $iv;

set iv_list_hex [split $pt_block_hex(0) {}];
set iv_rand {};
for {set i 0} {$i < 24} {incr i} {
    lappend iv_rand [lindex $iv_list_hex $i];
}
set iv_rand [join $iv_rand {}];
set iv_ctr 0;

set iv [join "$iv_rand [format %08x $iv_ctr]" {}];
my_puts $iv;

#set iv_binary [binary format H* $iv];
#puts -nonewline $p_fout $iv_binary;

for {set i 1} {$i < $pt_num_blocks} {incr i} {
    set my_xor_block($i) [aes::Encrypt $key [binary format H* $iv]];
    incr iv_ctr;
    set iv [join "$iv_rand [format %08x $iv_ctr]" {}];
    

    binary scan $my_xor_block($i) H* my_xor_block_hex($i);
    set pt_list_hex [split $pt_block_hex($i) {}];
    set xor_list_hex [split $my_xor_block_hex($i) {}];
    if {[llength $pt_list_hex] > [llength $xor_list_hex]} {
	set tlength [expr [llength $xor_list_hex]/2];
    } else {
	set tlength [expr [llength $pt_list_hex]/2]
    }
    
    set encoded_block_hex {};
    for {set j 0} {$j < $tlength} {incr j} {
	set a 0x[join "[lindex $pt_list_hex [expr $j * 2]] [lindex $pt_list_hex [expr $j * 2+1]]" {}];
	set b 0x[join "[lindex $xor_list_hex [expr $j * 2]] [lindex $xor_list_hex [expr $j * 2+1]]" {}];
	set c [expr $a ^ $b];
	lappend encoded_block_hex [format %02x $c];
	#puts "to_ascii $c = [to_ascii $c]";
	#puts -nonewline [to_ascii $c];
    }
    set encoded_block_hex [join $encoded_block_hex {}];
    set encoded_block_binary [binary format H* $encoded_block_hex]; 
    #set encoded_block_binary [binary format H* $pt_block_hex($i)]; 
    puts -nonewline $p_fout $encoded_block_binary;
    
}

close $p_fout;
