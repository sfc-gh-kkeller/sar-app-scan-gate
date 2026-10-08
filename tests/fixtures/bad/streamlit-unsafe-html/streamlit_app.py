import streamlit as st
name = st.text_input('name')
st.markdown(f'<b>Hello {name}</b>', unsafe_allow_html=True)
