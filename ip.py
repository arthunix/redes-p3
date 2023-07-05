from iputils import *
from ipaddress import ip_address, ip_network
from struct import pack

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identification = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dest_addr = struct.unpack('!BBHHHBBHII', datagrama[:20])

            ttl -= 1
            if ttl == 0:
                next_hop = self._next_hop(src_addr)

                # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
                # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
                checksum = calc_checksum(struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:64])
                icmp = struct.pack('!BBHI', 11, 0, checksum, 0) + datagrama[:64]
                checksum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, 20 + len(icmp), identification, flagsfrag, 64, 1, 0, int.from_bytes(str2addr(self.meu_endereco), "big"), src_addr))
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, 20 + len(icmp), identification, flagsfrag, 64, 1, checksum, int.from_bytes(str2addr(self.meu_endereco), "big"), src_addr) + icmp

                self.identification += 1
                self.enlace.enviar(datagrama, next_hop)
            else:
                checksum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, 0, src_addr, dest_addr))
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dest_addr) + datagrama[20:]
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        
        # PASSO 1 e PASSO 3
        next_hop = None
        prefix = aux = 0
        for tableItr in self.table:
            if ip_address(dest_addr) in ip_network(tableItr[0]):
                prefix = int(tableItr[0].split("/")[1])
                if prefix >= aux:
                    aux = prefix
                    next_hop = tableItr[1]
        return next_hop
        pass

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.table = tabela
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        # PASSO 2
        if(next_hop != None):
            # https://en.wikipedia.org/wiki/Internet_Protocol_version_4
            # https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets
            # 69d = 01000101b
            frame = struct.pack('!BBHHHBBH', 69, 0, 20 + len(segmento), self.identification, 0, 64, 6,                          \
                            calc_checksum(struct.pack('!BBHHHBBH', 69, 0, 20 + len(segmento), self.identification, 0, 64, 6, 0) \
                            + str2addr(self.meu_endereco)                                                                       \
                            + str2addr(dest_addr)))                                                                             \
                            + str2addr(self.meu_endereco)                                                                       \
                            + str2addr(dest_addr) + segmento
            self.enlace.enviar(frame, next_hop)
