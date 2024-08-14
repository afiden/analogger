#!/bin/bash

# Cores 

azul="\e[1;34m"
verde="\e[1;32m"
red="\e[1;31m"
reset="\e[0m"

# Payloads 

## Directory Travessel 

dirtr='(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)'

# Banners 

erro()
{
	echo -e "${red}Uso inválido. digite '$0 [Arquivo de log para leitura]'"
	echo -e "Exemplo: $0 /var/log/apache2/access.log${reset}"
}

exibir_informacoes() 
{
    echo -e "${verde}Informações do arquivo:${reset}"
    echo -e "Total de linhas: $(wc -l < "$1")"
    echo -e "Total de bytes: $(wc -c < "$1")"
}

opcoes_analise() {
    echo -e "${verde}Opções de Análise:${reset}"
    echo "[1] - Principais tipos de ataque"
    echo "[2] - IPS com mais requisições"
    echo "[3] - Total de códigos de status HTTP"
    echo "[4] - Recursos mais acessados"
    echo "[5] - Horários de Requisição do Atacante"
	echo "[6] - Sair"
}

# Script 


if [[ -f "$1" && "$1" == *.log ]]
then
	:
else
    erro
	exit
fi

while true; do
    opcoes_analise
    read -p "Escolha uma opção: " next_a

    if [ -z "$next_a" ]; then
        echo "Escolha inválida."
        continue

    elif [ "$next_a" == "1" ]; then
		clear
        echo -e "${red}Ataques de Directory Travessel:${reset}"
		ip_dirtr=$(grep -E $dirtr "$1" | cut -d " " -f 1 | sort -u)
		nt_dirtr=$(grep -E $dirtr "$1" | cut -d " " -f 1 | sort | uniq -c)
        totalatk=0
		nt_dirtr_t=$(echo $nt_dirtr | cut -d " " -f 1)
		t_dirtr=$(grep -c $dirtr "$1")
		for ips in $ip_dirtr; do
			for ntd in $nt_dirtr_t; do
				echo -e "Endereço IP: ${red}$ips${reset} Tentativas: ${red}$ntd${reset}"
                totalatk=$((totalatk + $ntd))
			done
		done
		echo -e "Total de Ataques: ${red}$totalatk${reset}"
		

    elif [ "$next_a" == "2" ]; then
        echo -e "${verde}IPs com mais requisições:${reset}"
        awk '{print $1}' "$1" | sort | uniq -c | sort -nr | head -n 10 | while read requis ip; do
            echo -e "Endereço IP: ${red}$ip${reset} Requisições: ${red}$requis${reset}"
        done

    elif [ "$next_a" == "3" ]; then
        echo -e "${verde} Escolha um código de status:${reset}"
        echo "[1] - Código 200"
        echo "[2] - Código 201"
        echo "[3] - Código 304"
        echo "[4] - Código 401"
        echo "[5] - Código 403"
        echo "[6] - Código 404"
        echo "[7] - Código 409"
        echo "[8] - Código 500"
        echo "[9] - Voltar"
        echo "Se o código não estiver presente, digite-o"
        read -p "Escolha um código: " bus_c
        
        if [ "$bus_c" == "9" ]; then
            :
        else
            echo -e "${verde}Requisições:${reset}"
        fi

        if [ "$bus_c" == "1" ]; then
            grep ' 200 ' $1
            total200=$(grep -c ' 200 ' $1)
            echo -e "${azul}Total de Requisições de código 200:${reset} $total200"
        elif [ "$bus_c" == "2" ]; then
            grep ' 201 ' $1
            total201=$(grep -c ' 201 ' $1)
            echo -e "${azul}Total de Requisições de código 201:${reset} $total201"
        elif [ "$bus_c" == "3" ]; then
            grep ' 304 ' $1
            total304=$(grep -c ' 304 ' $1)
            echo -e "${azul}Total de Requisições de código 304:${reset} $total304"
        elif [ "$bus_c" == "4" ]; then
            grep ' 401 ' $1
            total401=$(grep -c ' 401 ' $1)
            echo -e "${azul}Total de Requisições de código 401:${reset} $total401"
        elif [ "$bus_c" == "5" ]; then
            grep ' 403 ' $1
            total403=$(grep -c ' 403 ' $1)
            echo -e "${azul}Total de Requisições de código 403:${reset} $total403"
        elif [ "$bus_c" == "6" ]; then
            grep ' 404 ' $1
            total404=$(grep -c ' 404 ' $1)
            echo -e "${azul}Total de Requisições de código 404:${reset} $total404"
        elif [ "$bus_c" == "7" ]; then
            grep ' 409 ' $1
            total409=$(grep -c ' 409 ' $1)
            echo -e "${azul}Total de Requisições de código 409:${reset} $total409"
        elif [ "$bus_c" == "8" ]; then
            grep ' 500 ' $1
            total500=$(grep -c ' 500 ' $1)
            echo -e "${azul}Total de Requisições de código 500:${reset} $total500"
        elif [ "$bus_c" == "9" ]; then
            echo "Voltando ao menu principal.."
        else
            grep " $bus_c " $1
            total_custom=$(grep -c " $bus_c " $1)
            echo -e "${azul}Total de Requisições de código ${bus_c}:${reset} $total_custom"
        fi

    elif [ "$next_a" == "4" ]; then
        echo -e "${verde}Recursos mais acessados:${reset}"
        awk '{print $7}' "$1" | sort | uniq -c | sort -nr | head -n 100 | while read count pag; do
            echo -e "Página: ${azul}$pag${reset} Acessos: ${azul}$count${reset}"
        done
        
    elif [ "$next_a" == "5" ]; then
        echo -e "${verde} Escolha um código de status:${reset}"
        echo "[1] - Todos os IP's"
        echo "[2] - Escolher um IP"
        echo "[3] - Voltar"
        read -p "Escolha um código: " cons_ip

        if [ "$cons_ip" == "3" ]; then
            :
        fi

        if [ "$cons_ip" == "1" ]; then
            ip_dirtr=$(grep -E $dirtr "$1" | cut -d " " -f 1 | sort -u)
            for ips in $ip_dirtr; do
                echo -e "Endereço IP: ${red}$ips${reset}"
                primre=$(grep -E $ips "$1" | head -n 1 | awk '{print $4}' | cut -c 2-)
                ultre=$(grep -E $ips "$1" | tail -n 1 | awk '{print $4}' | cut -c 2-)
                totalre=$(grep -c $ips "$1")
                echo -e "Primeira Requisição: ${red}$primre${reset}"
                echo -e "Ultima Requisição: ${red}$ultre${reset}"
                echo -e "Total de Requisições: ${red}$totalre${reset}"
                echo -e "=============================="
            done

        elif [ "$cons_ip" == "2" ]; then
            read -p "Digite o Endereço IP: " en_ip

            en_ip2=$(grep -E $en_ip "$1" | cut -d " " -f 1 | sort -u)
            for ips in $en_ip2; do
                echo -e "=============================="
                echo -e "Endereço IP: ${red}$ips${reset}"
                primre=$(grep -E $ips "$1" | head -n 1 | awk '{print $4}' | cut -c 2-)
                ultre=$(grep -E $ips "$1" | tail -n 1 | awk '{print $4}' | cut -c 2-)
                totalre=$(grep -c $ips "$1")
                echo -e "Primeira Requisição: ${red}$primre${reset}"
                echo -e "Ultima Requisição: ${red}$ultre${reset}"
                echo -e "Total de Requisições: ${red}$totalre${reset}"
                echo -e "=============================="
            done

        else
            :
        fi

    elif [ "$next_a" == "6" ]; then
        echo -e "${red}Encerrando...${reset}"
        sleep 2
        break
    else
        echo "Escolha inválida."
    fi
done
