#include "arp.h"


struct ether_header *
ether_header_new( const u_char *src_mac ) 
{
      struct ether_header * ether_header_p = \
            ( struct ether_header * ) malloc( sizeof( struct ether_header ) );

      if ( NULL == ether_header_p ) return ( NULL );

      memset( ether_header_p->ether_dhost, 255, ETHER_ADDR_LEN );
      memcpy( ether_header_p->ether_shost, src_mac, ETHER_ADDR_LEN );
      ether_header_p->ether_type = htons( _ARP );

      return ( ether_header_p );
}


struct ether_arp * 
ether_arp_new( const u_char *src_mac , const u_char *src_ip, const u_char *dst_ip )  
{
      struct ether_arp * ether_arp_p = ( struct ether_arp * ) \
            malloc( sizeof( struct ether_arp ) );

      if ( NULL == ether_arp_p ) return ( NULL ); 

      ether_arp_p->ea_hdr.ar_hrd = htons( ARPHRD_ETHER );
      ether_arp_p->ea_hdr.ar_pro = htons( _IPv4 );
      ether_arp_p->ea_hdr.ar_hln = 6;
      ether_arp_p->ea_hdr.ar_pln = 4;
      ether_arp_p->ea_hdr.ar_op  = htons( ARPOP_REQUEST );
      
      memcpy( ether_arp_p->arp_sha, src_mac, ETHER_ADDR_LEN );
      memcpy( ether_arp_p->arp_spa, src_ip, 4 );

      bzero( ether_arp_p->arp_tha, ETHER_ADDR_LEN );
      memcpy( ether_arp_p->arp_tpa, dst_ip, 4 );

      return ( ether_arp_p );

}


int get_locator_address( const char *if_name, u_char *local_mac, u_char *local_ip )
{
      struct sockaddr_in *addr;
      struct ifaddrs *ifadr, *if_list;
    
      if( getifaddrs( &if_list ) < 0 )
            return ( errno );

      for ( ifadr = if_list; ifadr != NULL; ifadr = ifadr->ifa_next )
      {
            if ( strcmp( if_name, ifadr->ifa_name ) == 0 )
            {
                  if( !IS_EMPTY_MAC( local_mac ) && ifadr->ifa_addr->sa_family == AF_LINK )  
                        memcpy( local_mac, (u_char *)LLADDR((struct sockaddr_dl *)( ifadr )->ifa_addr), ETHER_ADDR_LEN ); 

                  if ( !IS_EMPTY_IP( local_ip ) && ifadr->ifa_addr->sa_family == AF_INET )
                        uint32_to_array( ntohl( ( ( struct sockaddr_in * ) ifadr->ifa_addr )->sin_addr.s_addr ), local_ip );
            }
      }
      
      return ( 0 );
}     

void 
pcap_capture_callback( u_char *user, const struct pcap_pkthdr *h, const u_char *bytes )
{
      if ( h->caplen <= 0 || h->caplen < FRAME_SIZE ) return;

      struct ether_arp *rsp = ( struct ether_arp * ) ( bytes + sizeof( struct ether_header ) );

      fprintf(stdout, "Target IP: %d.%d.%d.%d\n"
                        "Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        rsp->arp_spa[0], rsp->arp_spa[1], rsp->arp_spa[2], rsp->arp_spa[3],
                        rsp->arp_sha[0], rsp->arp_sha[1], rsp->arp_sha[2], rsp->arp_sha[3],
                        rsp->arp_sha[4], rsp->arp_sha[5]);

}

int
send_frame_and_capture( char *if_name, u_char *buffer, u_int size, char *dst_ip)
{
      char err_buf[PCAP_ERRBUF_SIZE] = {0}, filter_rule[40] = {0};
      struct bpf_program fp;
      
      int ret = 0;
      pcap_t *pcap = pcap_open_live( if_name, 65535, 1, 100, err_buf );

      if ( *err_buf ) 
      {
            fprintf( stderr, "%s\n", err_buf);
            return ( -1 );
      } 

      sprintf( filter_rule, "arp src host %s", dst_ip );

      if ( ( ret = pcap_compile( pcap, &fp, filter_rule, 1, 0 ) ) == PCAP_ERROR )
      {
            fprintf( stderr, "%s\n", pcap_geterr( pcap ) );
            goto close;
      }

      if ( ( ret = pcap_setfilter( pcap, &fp ) ) == PCAP_ERROR ) 
      {
            fprintf( stderr, "%s\n", pcap_geterr( pcap ) );
            goto close;
      }

      // Inject the filled packet into the target interface by pcap
      if ( ( ret = pcap_inject( pcap, buffer, size ) ) == PCAP_ERROR ) 
      {
            fprintf( stderr, "%s\n", pcap_geterr( pcap ) );
            goto close;
      }

      // Set timeout value of 1 second before doing a live capture
      if ( ( ret = pcap_set_timeout( pcap, 1000 ) ) == PCAP_ERROR )
      {
            fprintf( stderr, "%s\n", pcap_geterr( pcap ) );
            goto close;
      }

      if ( ( ret = pcap_dispatch( pcap, -1, pcap_capture_callback, NULL ) ) <= 0 ) 
      {
            if (ret) fprintf( stderr, "%s\n", pcap_geterr( pcap ) );
            else fprintf( stdout, "Received timeout\n" );
            goto close;
      }

      close:
            pcap_close( pcap );
            return ( ret );
}

void 
uint32_to_array( uint32_t u, u_char * a)
{
      *a = ( u >> 24 ) & 0xff;
      *( a + 1 ) = ( u >> 16 ) & 0xff;
      *( a + 2 ) = ( u >> 8 ) & 0xff;
      *( a + 3 ) = ( u ) & 0xff;
}

int 
parse_ip_to_array( const char *ip, u_char *ipp)
{
      if (!ip || !*ip ) return ( -1 );

      uint32_t addr = inet_addr(ip);
      uint32_to_array( ntohl(addr), ipp );

      if (addr < 0 ) return ( -1 );
      
      return ( 0 );
}
/**
 * @param ins_name Constant string pointer, Network card interface 
 * @param dst_ip Constant string pointer, Dstination host's IPv4 address
 * @return if successfully it returns Ok(value 0),
 * otherwise, returns error code(value >= 1)
*/

int arp_run
( const char *if_name, const char *dst_ip )
{
      if ( if_name == NULL || dst_ip == NULL ) 
            return ( 1 );
      
      if ( !( *if_name ) || !( *dst_ip ))
            return ( 1 );

      u_char local_mac[ETHER_ADDR_LEN], local_ip[4], dst_ipp[4], buffer[BUFSIZ];
      int ret = 0;

      if ( parse_ip_to_array( dst_ip, dst_ipp ) ) return ( 1 );

      if ( get_locator_address( if_name, local_mac, local_ip ) )
            return ( 1 );

      struct ether_header *ether_header_p = ether_header_new( local_mac );
      struct ether_arp *ether_arp_p = ether_arp_new( local_mac, local_ip, dst_ipp );

      memcpy( buffer, ether_header_p, sizeof( struct ether_header ) );
      memcpy( buffer + sizeof( struct ether_header ), ether_arp_p, sizeof( struct ether_arp ) );

      #ifdef DEBUG
      printf( "Ethernet frame(sender): \n" );
      for ( int i = 0; i < FRAME_SIZE; i++)
            printf("%02x ", buffer[i] );
      
      printf( "\n" );
      #endif // DEBUG

      // Release allocted memeory after copying data to a buffer.
      free( ether_header_p );
      free( ether_arp_p );

      if ( send_frame_and_capture( if_name, buffer, FRAME_SIZE, dst_ip ) )
            return ( 1 );
      return ( 0 );
}

int main(int argc, char** argv)
{
      if ( argc < 3 ) 
      {
            printf("Usage: arp [interface] [target ip]\n");
            return ( 0 );
      }
      return ( arp_run( argv[1], argv[2] ) );
}